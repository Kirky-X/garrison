//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 社交登录 provider 名称校验工具。
//!
//! 提供 [`crate::protocol::social::validation::is_valid_provider_name`] 函数，校验 provider 标识符格式合法性。
//! 供 garrison 内部与外部 crate（如 sinnan）共用，确保 provider 名称校验规则
//! 单一来源（DIP：校验规则由社交登录域定义，消费方复用）。

// ============================================================================
// provider 名称校验
// ============================================================================

/// provider 名称最大长度（字节）。
///
/// 32 字节覆盖所有已知社交平台标识（wechat/alipay/huawei/wechat_mini_app），
/// 同时防止超长字符串攻击（内存消耗、日志膨胀、DAO key 注入）。
const MAX_PROVIDER_NAME_LEN: usize = 32;

/// 校验 provider 名称格式合法性。
///
/// # 合法格式
///
/// - 非空，长度 1-32 字节
/// - 首字符必须是小写字母（`a-z`）
/// - 其余字符仅允许小写字母（`a-z`）、数字（`0-9`）、下划线（`_`）
///
/// # 安全考量
///
/// - **日志注入**：禁止换行符、控制字符，防止伪造日志条目
/// - **DAO key 注入**：禁止冒号（`:`）、空格等 key 分隔符
/// - **SQL 注入**：禁止分号、引号等 SQL 元字符
/// - **超长攻击**：长度上限 32 字节，防止内存消耗与日志膨胀
/// - **大小写一致性**：仅允许小写，与 `provider_names` 常量（`"wechat"` 等）对齐
///
/// # 参数
///
/// - `provider`: provider 标识符（如 `"wechat"` / `"huawei"`）
///
/// # 返回
///
/// - `true`：名称合法
/// - `false`：名称非法（调用方应返回 400 Bad Request）
///
/// # 示例
///
/// ```
/// use garrison::protocol::social::validation::is_valid_provider_name;
///
/// assert!(is_valid_provider_name("wechat"));
/// assert!(is_valid_provider_name("huawei"));
/// assert!(!is_valid_provider_name(""));
/// assert!(!is_valid_provider_name("WeChat"));
/// ```
pub fn is_valid_provider_name(provider: &str) -> bool {
    if provider.is_empty() || provider.len() > MAX_PROVIDER_NAME_LEN {
        return false;
    }
    let mut chars = provider.chars();
    // 首字符必须是小写字母
    if !chars
        .next()
        .map(|c| c.is_ascii_lowercase())
        .unwrap_or(false)
    {
        return false;
    }
    // 其余字符必须是小写字母/数字/下划线
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 合法 provider 名称应返回 true。
    #[test]
    fn is_valid_provider_name_accepts_valid_names() {
        assert!(is_valid_provider_name("wechat"), "'wechat' 应合法");
        assert!(is_valid_provider_name("huawei"), "'huawei' 应合法");
        assert!(is_valid_provider_name("alipay"), "'alipay' 应合法");
        assert!(is_valid_provider_name("a"), "单字符小写字母应合法");
        assert!(is_valid_provider_name("a1"), "字母+数字应合法");
        assert!(is_valid_provider_name("a_b"), "字母+下划线应合法");
        assert!(
            is_valid_provider_name("wechat_mini_app"),
            "多段下划线应合法"
        );
        assert!(
            is_valid_provider_name(&"a".repeat(32)),
            "32 字符（上限边界）应合法"
        );
    }

    /// 非法 provider 名称应返回 false。
    #[test]
    fn is_valid_provider_name_rejects_invalid_names() {
        // 空字符串
        assert!(!is_valid_provider_name(""), "空字符串应拒绝");
        // 首字符非小写字母
        assert!(!is_valid_provider_name("A"), "大写字母开头应拒绝");
        assert!(!is_valid_provider_name("1abc"), "数字开头应拒绝");
        assert!(!is_valid_provider_name("_abc"), "下划线开头应拒绝");
        assert!(!is_valid_provider_name("-abc"), "连字符开头应拒绝");
        // 含大写字母
        assert!(!is_valid_provider_name("weChat"), "含大写字母应拒绝");
        assert!(!is_valid_provider_name("Wechat"), "首字母大写应拒绝");
        // 含特殊字符（日志注入/DAO key 注入风险）
        assert!(!is_valid_provider_name("a!"), "含感叹号应拒绝");
        assert!(!is_valid_provider_name("a:b"), "含冒号应拒绝");
        assert!(!is_valid_provider_name("a-b"), "含连字符应拒绝");
        assert!(!is_valid_provider_name("a.b"), "含点号应拒绝");
        assert!(!is_valid_provider_name("a b"), "含空格应拒绝");
        assert!(
            !is_valid_provider_name("a\nb"),
            "含换行符应拒绝（日志注入）"
        );
        assert!(
            !is_valid_provider_name("wechat;DROP TABLE"),
            "含 SQL 注入字符应拒绝"
        );
        // 超长（>32 字符）
        assert!(
            !is_valid_provider_name(&"a".repeat(33)),
            "33 字符应拒绝（超长攻击）"
        );
    }
}
