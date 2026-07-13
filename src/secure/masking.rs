//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 敏感数据脱敏子模块。
//!
//! 提供 `SensitiveDataMasker` 对手机号 / 身份证 / 邮箱 / 银行卡等敏感字段进行脱敏，
//! 支持对 `serde_json::Value` 递归脱敏。
//!
//! - `MaskType` 枚举定义脱敏类型，`SensitiveDataMasker` 持有 `(MaskType, field_name)` 规则列表
//! - `mask_value` 对单个字符串值按指定类型脱敏
//! - `mask_json` 递归遍历 JSON Object，匹配 field 名后调用 `mask_value`
//! - `Custom(String)` 变体仅存储正则模式字符串，不实现实际脱敏（返回原值 + warn 日志）

use serde_json::Value;

/// 脱敏类型枚举。
///
/// 定义常见敏感字段的脱敏策略。`Custom` 变体预留正则模式字符串，
/// 本批次不实现实际脱敏逻辑（返回原值并记录 `tracing::warn`）。
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
    /// 自定义正则模式（本批次不实现，返回原值 + warn 日志）。
    Custom(String),
}

/// 敏感数据脱敏器。
///
/// 持有 `(MaskType, field_name)` 规则列表，对 JSON Object 递归脱敏。
///
/// # 示例
///
/// ```ignore
/// use bulwark::secure::masking::{MaskType, SensitiveDataMasker};
/// use serde_json::json;
///
/// let masker = SensitiveDataMasker::new()
///     .with_rule(MaskType::Phone, "phone");
/// let input = json!({"phone": "13812341234"});
/// let masked = masker.mask_json(&input);
/// assert_eq!(masked, json!({"phone": "138****1234"}));
/// ```
#[derive(Debug, Clone, Default)]
pub struct SensitiveDataMasker {
    /// 脱敏规则列表：`(脱敏类型, 字段名)`。
    rules: Vec<(MaskType, &'static str)>,
}

impl SensitiveDataMasker {
    /// 创建空的脱敏器（无规则）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 添加脱敏规则（builder 模式）。
    ///
    /// # 参数
    /// - `mask_type`: 脱敏类型。
    /// - `field_name`: JSON Object 中需脱敏的字段名（`&'static str`）。
    pub fn with_rule(mut self, mask_type: MaskType, field_name: &'static str) -> Self {
        self.rules.push((mask_type, field_name));
        self
    }

    /// 对单个字符串值按指定脱敏类型脱敏。
    ///
    /// # 参数
    /// - `value`: 待脱敏的字符串。
    /// - `mask_type`: 脱敏类型。
    ///
    /// # 返回
    /// 脱敏后的字符串。不满足最小长度要求时返回原值。
    pub fn mask_value(&self, value: &str, mask_type: &MaskType) -> String {
        match mask_type {
            MaskType::Phone => mask_phone(value),
            MaskType::IdCard => mask_id_card(value),
            MaskType::Email => mask_email(value),
            MaskType::BankCard => mask_bank_card(value),
            MaskType::Custom(_) => {
                tracing::warn!("Custom mask type not implemented in this batch");
                value.to_string()
            },
        }
    }

    /// 按 field 名匹配规则脱敏单个值。
    ///
    /// 遍历规则列表，找到第一个 field 名匹配的规则，按其 MaskType 脱敏。
    /// 无匹配规则时返回原值。
    ///
    /// # 参数
    /// - `field`: 字段名。
    /// - `value`: 待脱敏的字符串。
    ///
    /// # 返回
    /// 脱敏后的字符串。无匹配规则或非字符串类型时返回原值。
    pub fn mask_field(&self, field: &str, value: &str) -> String {
        match self.rules.iter().find(|(_, name)| *name == field) {
            Some((mask_type, _)) => self.mask_value(value, mask_type),
            None => value.to_string(),
        }
    }

    /// 递归脱敏 JSON Value。
    ///
    /// 遍历 Object 字段，匹配规则中的 field 名后调用 `mask_value` 脱敏。
    /// 嵌套 Object 与数组中的 Object 均递归处理；非 Object 类型返回原值。
    ///
    /// # 参数
    /// - `value`: 待脱敏的 JSON Value。
    ///
    /// # 返回
    /// 脱敏后的 JSON Value（深拷贝）。
    pub fn mask_json(&self, value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (key, val) in map {
                    let recursed = self.mask_json(val);
                    let final_val = if let Some((mask_type, _)) =
                        self.rules.iter().find(|(_, name)| *name == key.as_str())
                    {
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

/// 手机号脱敏：保留前 3 后 4，中间 `*` 填充。少于 7 位返回原值。
///
/// 使用 `chars()` 按字符索引切片，避免非 ASCII 字符（如中文、emoji）在字符中间
/// 切割导致 panic。
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

/// 身份证号脱敏：保留前 3 后 4，中间 `*` 填充。少于 7 位返回原值。
///
/// 使用 `chars()` 按字符索引切片，避免非 ASCII 字符在字符中间切割导致 panic。
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

/// 银行卡号脱敏（PCI-DSS 3.4）：保留前 6 后 4，中间 `*` 填充。少于 10 位返回全 `*`。
///
/// PCI-DSS 3.4 要求银行卡号展示时最多显示 first 6 + last 4（共 10 位），
/// 中间部分必须用 `*` 屏蔽。当输入长度 < 10 时无法安全拆分 first 6 + last 4，
/// 全部字符以 `*` 屏蔽（长度与输入一致，避免长度泄漏）。
///
/// 使用 `chars()` 按字符索引切片，避免非 ASCII 字符在字符中间切割导致 panic。
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ========================================================================
    // mask_value 测试（T001）
    // ========================================================================

    /// T001-1: 手机号 "13812341234" → "138****1234"。
    #[test]
    fn mask_phone_returns_138_1234() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("13812341234", &MaskType::Phone);
        assert_eq!(result, "138****1234");
    }

    /// T001-2: 身份证 "110101199001011234" → "110***********1234"。
    #[test]
    fn mask_id_card_returns_masked() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("110101199001011234", &MaskType::IdCard);
        assert_eq!(result, "110***********1234");
    }

    /// T001-3: 邮箱 "alice@example.com" → "a***@example.com"。
    #[test]
    fn mask_email_returns_masked() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("alice@example.com", &MaskType::Email);
        assert_eq!(result, "a***@example.com");
    }

    /// T001-4: 银行卡 "6222021234567890" → "622202******7890"（PCI-DSS first 6 + last 4）。
    #[test]
    fn mask_bank_card_returns_masked() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("6222021234567890", &MaskType::BankCard);
        assert_eq!(result, "622202******7890");
    }

    /// T001-5: Custom 类型返回原值（本批次不实现实际脱敏）。
    #[test]
    fn mask_custom_returns_original() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("sensitive", &MaskType::Custom(r"\d+".to_string()));
        assert_eq!(result, "sensitive");
    }

    /// T001-6: 手机号少于 7 位返回原值。
    #[test]
    fn mask_phone_short_returns_original() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("123456", &MaskType::Phone);
        assert_eq!(result, "123456");
    }

    /// T001-7: 身份证少于 7 位返回原值。
    #[test]
    fn mask_id_card_short_returns_original() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("123456", &MaskType::IdCard);
        assert_eq!(result, "123456");
    }

    /// T001-8: 邮箱无 `@` 返回原值。
    #[test]
    fn mask_email_no_at_returns_original() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("noemail", &MaskType::Email);
        assert_eq!(result, "noemail");
    }

    /// T001-9: 邮箱 `@` 在首位（无本地部分）返回原值。
    #[test]
    fn mask_email_at_start_returns_original() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("@example.com", &MaskType::Email);
        assert_eq!(result, "@example.com");
    }

    /// T001-10: 银行卡少于 10 位返回全 `*`（PCI-DSS 3.4：不足 first 6 + last 4 时全屏蔽）。
    #[test]
    fn mask_bank_card_short_returns_all_stars() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("1234567", &MaskType::BankCard);
        assert_eq!(result, "*******");
    }

    /// T002-1: PCI-DSS 3.4 银行卡脱敏 first 6 + last 4：
    /// "6225881234567890"（16 位）→ "622588******7890"（前 6 + 中 6 星 + 后 4）。
    #[test]
    fn mask_bank_card_pci_dss_first6_last4() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("6225881234567890", &MaskType::BankCard);
        assert_eq!(result, "622588******7890");
    }

    /// T002-2: PCI-DSS 边界 — 恰好 10 位时 first 6 + last 4 中间 0 星。
    #[test]
    fn mask_bank_card_pci_dss_boundary_10_chars() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("6225887890", &MaskType::BankCard);
        assert_eq!(result, "6225887890");
    }

    /// T002-3: PCI-DSS 边界 — 9 位（< 10）返回全 `*`，长度与输入一致。
    #[test]
    fn mask_bank_card_pci_dss_short_9_chars_all_stars() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("622588789", &MaskType::BankCard);
        assert_eq!(result, "*********");
    }

    /// T002-4: PCI-DSS 边界 — 空字符串返回空（长度 0 < 10，全 `*` 即空串）。
    #[test]
    fn mask_bank_card_pci_dss_empty_string() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("", &MaskType::BankCard);
        assert_eq!(result, "");
    }

    /// T001-11: 手机号含多字节字符（中文）不应 panic。
    /// "ab中cdefg" 字节 2..5 为 "中"（3 字节），旧实现 `&value[..3]` 切到字符中间会 panic。
    #[test]
    fn mask_phone_handles_multibyte_input() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("ab中cdefg", &MaskType::Phone);
        assert!(!result.is_empty(), "多字节输入不应 panic 且应返回非空结果");
    }

    /// T001-12: 身份证含多字节字符不应 panic。
    #[test]
    fn mask_id_card_handles_multibyte_input() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("ab中cdefg", &MaskType::IdCard);
        assert!(!result.is_empty(), "多字节输入不应 panic 且应返回非空结果");
    }

    /// T001-13: 银行卡含多字节字符不应 panic。
    /// "ab中cdefg" 字节 2..5 为 "中"，旧实现 `&value[..4]` 切到字符中间会 panic。
    #[test]
    fn mask_bank_card_handles_multibyte_input() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("ab中cdefg", &MaskType::BankCard);
        assert!(!result.is_empty(), "多字节输入不应 panic 且应返回非空结果");
    }

    // ========================================================================
    // mask_field 测试
    // ========================================================================

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

    // ========================================================================
    // mask_json 测试（T002）
    // ========================================================================

    /// T002-1: `{"phone":"13812341234"}` → `{"phone":"138****1234"}`。
    #[test]
    fn mask_json_masks_phone_field() {
        let masker = SensitiveDataMasker::new().with_rule(MaskType::Phone, "phone");
        let input = json!({"phone": "13812341234"});
        let masked = masker.mask_json(&input);
        assert_eq!(masked, json!({"phone": "138****1234"}));
    }

    /// T002-2: 嵌套 Object 递归脱敏。
    #[test]
    fn mask_json_masks_nested_object() {
        let masker = SensitiveDataMasker::new().with_rule(MaskType::Phone, "phone");
        let input = json!({"user": {"phone": "13812341234"}});
        let masked = masker.mask_json(&input);
        assert_eq!(masked, json!({"user": {"phone": "138****1234"}}));
    }

    /// T002-3: 数组中的 Object 递归脱敏。
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

    /// T002-4: 非 Object 类型返回原值。
    #[test]
    fn mask_json_non_object_returns_original() {
        let masker = SensitiveDataMasker::new();
        let input = json!("just a string");
        let masked = masker.mask_json(&input);
        assert_eq!(masked, input);
    }

    /// T002-5: 无匹配字段返回原值。
    #[test]
    fn mask_json_no_matching_field_returns_original() {
        let masker = SensitiveDataMasker::new().with_rule(MaskType::Phone, "phone");
        let input = json!({"name": "Alice"});
        let masked = masker.mask_json(&input);
        assert_eq!(masked, json!({"name": "Alice"}));
    }

    /// T002-6: 多字段混合脱敏（phone + email + 非敏感字段）。
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
}
