//! 密码策略错误类型（v0.6.0 新增，依据 spec password-policy R-004）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 定义 [`PolicyError`]，由 `PasswordPolicyRule::validate` 返回，
//! `PasswordPolicyEngine::validate` 收集为 `Vec<PolicyError>`。

use std::fmt;

/// 密码策略校验错误（依据 spec password-policy R-004）。
///
/// 由规则 `validate` 返回，含触发规则的名称与可展示给用户的错误描述。
///
/// # 字段
///
/// - `rule_name`: 触发错误的规则名称（对应 `PasswordPolicyRule::name()` 返回值）
/// - `message`: 错误描述信息（可展示给用户）
#[derive(Debug, Clone)]
pub struct PolicyError {
    /// 触发错误的规则名称。
    pub rule_name: String,
    /// 错误描述信息（可展示给用户）。
    pub message: String,
}

impl PolicyError {
    /// 创建 `PolicyError`。
    ///
    /// # 参数
    /// - `rule_name`: 触发错误的规则名称。
    /// - `message`: 错误描述信息。
    pub fn new(rule_name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            rule_name: rule_name.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.rule_name, self.message)
    }
}

impl std::error::Error for PolicyError {}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// R-004: `PolicyError::new` 构造正确字段。
    #[test]
    fn policy_error_new_sets_fields() {
        let err = PolicyError::new("length", "密码长度不足");
        assert_eq!(err.rule_name, "length");
        assert_eq!(err.message, "密码长度不足");
    }

    /// R-004: `PolicyError` 实现 `Display`，输出含 `rule_name` 与 `message`。
    #[test]
    fn policy_error_display_contains_rule_name_and_message() {
        let err = PolicyError::new("complexity", "需包含大写字母");
        let display = format!("{}", err);
        assert!(
            display.contains("complexity"),
            "Display 输出应含 rule_name: {}",
            display
        );
        assert!(
            display.contains("需包含大写字母"),
            "Display 输出应含 message: {}",
            display
        );
    }

    /// R-004: `PolicyError` Clone 后字段一致。
    #[test]
    fn policy_error_clone_preserves_fields() {
        let err = PolicyError::new("blacklist", "密码在黑名单中");
        let cloned = err.clone();
        assert_eq!(cloned.rule_name, err.rule_name);
        assert_eq!(cloned.message, err.message);
    }
}
