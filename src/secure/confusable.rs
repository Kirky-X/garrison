//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Unicode 同形异义字检测子模块（0.5.1 新增，依据 design.md D10，L6）。
//!
//! 提供 `check_confusable` 函数，检测字符串中的 Unicode 同形异义字
//! （homoglyphs，如 Cyrillic `а` U+0430 与 Latin `a` U+0061 视觉相同）。
//!
//! ## 设计
//!
//! - 使用 `unicode-security` crate 0.1 的 Confusables database（Unicode TR39）
//! - 对输入字符串逐字符扫描，通过 `skeleton` 算法计算每个字符的可疑替身
//! - 当字符的 skeleton 与原字符不同时，生成 `ConfusableWarning` 警告
//!
//! ## 集成
//!
//! 启用 `secure-confusable` feature 后，`PermissionRegistry::register`
//! 会自动调用 `check_confusable` 检测 permission name，发现可疑字符时通过 `tracing::warn` 上报
//! （不阻止注册，仅警告）。

use unicode_security::confusable_detection::skeleton;

/// 单个 Unicode 同形异义字警告（依据 design.md D10）。
///
/// 由 [`check_confusable`] 返回，描述字符串中某个字符的可疑替身信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfusableWarning {
    /// 字符在原字符串中的字节位置（与 `str::char_indices` 一致）。
    pub position: usize,
    /// 原始字符（可疑字符本身）。
    pub char: char,
    /// 易混淆的目标字符（如 Cyrillic `а` → Latin `a`）。
    pub confusable_with: char,
    /// 建议替换的可读字符串（如 `"考虑用 'a' 替换 'а'"`）。
    pub suggestion: String,
}

/// 检测字符串中的 Unicode 同形异义字（依据 design.md D10，L6）。
///
/// 对输入字符串逐字符扫描，使用 `unicode-security` crate 的 TR39 Confusables database
/// 检测视觉相似但实际不同的字符。常见场景：Cyrillic `а` (U+0430) 与 Latin `a` (U+0061)
/// 视觉相同但属于不同脚本，可能导致权限名/用户名仿冒攻击。
///
/// # 参数
/// - `s`: 待检测的字符串。
///
/// # 返回
/// - `Vec<ConfusableWarning>`: 所有可疑字符的警告列表。空 Vec 表示无可疑字符。
///
/// # 算法
///
/// 对每个字符 `c`，调用 `unicode_security::confusable_detection::skeleton(&c.to_string())`
/// 计算 TR39 骨架。当骨架为单字符且与原字符不同时，判定为同形异义字。
/// 多字符骨架（如 NFC 组合字符 `á` 经 NFD 分解为 `a` + 组合重音符）会被跳过，
/// 避免对合法组合字符产生误报。
///
/// # 示例
///
/// ```ignore
/// use bulwark::secure::confusable::check_confusable;
///
/// // 纯 ASCII 字符串无警告
/// assert!(check_confusable("user:read").is_empty());
///
/// // 含 Cyrillic 'а' (U+0430) 的字符串返回警告
/// let warnings = check_confusable("аdmin"); // 第一个字符是 Cyrillic 'а'
/// assert_eq!(warnings.len(), 1);
/// assert_eq!(warnings[0].confusable_with, 'a'); // Latin 'a'
/// ```
pub fn check_confusable(s: &str) -> Vec<ConfusableWarning> {
    let mut warnings = Vec::new();
    for (byte_pos, c) in s.char_indices() {
        // 计算单字符的 TR39 骨架（含 NFD 规范化 + confusables 原型查找）
        let skel: String = skeleton(&c.to_string()).collect();
        // 仅当骨架为单字符且与原字符不同时判定为同形异义字。
        // 多字符骨架（如 NFD 分解的组合字符）跳过，避免误报。
        let mut skel_chars = skel.chars();
        if let Some(skel_char) = skel_chars.next() {
            if skel_char != c && skel_chars.next().is_none() {
                warnings.push(ConfusableWarning {
                    position: byte_pos,
                    char: c,
                    confusable_with: skel_char,
                    suggestion: format!("考虑用 '{}' 替换 '{}'", skel_char, c),
                });
            }
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // T083: check_confusable 测试（Red 阶段，依据 design.md D10）
    // ========================================================================

    /// T083-1: 纯 ASCII 字符串（如 "user:read"）返回空 Vec（无可疑字符）。
    #[test]
    fn check_confusable_returns_empty_for_pure_ascii() {
        let warnings = check_confusable("user:read");
        assert!(
            warnings.is_empty(),
            "纯 ASCII 字符串不应有可疑字符: {:?}",
            warnings
        );
    }

    /// T083-2: 含 Latin 'a' (U+0061) 与 Cyrillic 'а' (U+0430) 混合时返回警告。
    ///
    /// Cyrillic 'а' (U+0430) 视觉与 Latin 'a' (U+0061) 相同，应被检测为可疑。
    #[test]
    fn check_confusable_returns_warning_for_homoglyph() {
        // "aа" — Latin 'a' + Cyrillic 'а' (U+0430)
        let input = "a\u{0430}";
        let warnings = check_confusable(input);
        assert!(!warnings.is_empty(), "应检测到 Cyrillic 'а' 可疑字符");
        let cyrillic_warning = warnings
            .iter()
            .find(|w| w.char == '\u{0430}')
            .expect("应包含 Cyrillic 'а' (U+0430) 的警告");
        assert_eq!(
            cyrillic_warning.confusable_with, 'a',
            "Cyrillic 'а' 应混淆为 Latin 'a'"
        );
    }

    /// T083-3: 混合字符串 "аdmin"（首字符为 Cyrillic 'а' U+0430）返回警告。
    ///
    /// 模拟攻击者用 Cyrillic 'а' 替换 Latin 'a' 仿冒 "admin" 权限名。
    #[test]
    fn check_confusable_returns_warning_for_mixed_script() {
        // "аdmin" — 首字符 Cyrillic 'а' (U+0430) + Latin "dmin"
        let input = "\u{0430}dmin";
        let warnings = check_confusable(input);
        assert!(!warnings.is_empty(), "混合字符串应检测到可疑字符");
        let first = &warnings[0];
        assert_eq!(first.char, '\u{0430}', "首字符应为 Cyrillic 'а'");
        assert_eq!(first.confusable_with, 'a', "应混淆为 Latin 'a'");
        assert_eq!(first.position, 0, "首字符字节位置应为 0");
    }

    /// T083-4: 空字符串返回空 Vec（边界条件）。
    #[test]
    fn check_confusable_returns_empty_for_empty_string() {
        let warnings = check_confusable("");
        assert!(warnings.is_empty(), "空字符串不应有可疑字符");
    }

    /// T083-5: 多个同形异义字返回多个警告。
    ///
    /// "аdmin" 含 Cyrillic 'а' (U+0430) → Latin 'a'，再加 Cyrillic 'о' (U+043E) → Latin 'o'。
    #[test]
    fn check_confusable_returns_multiple_warnings_for_multiple_homoglyphs() {
        // "аdоmin" — Cyrillic 'а' (U+0430) + Latin 'd' + Cyrillic 'о' (U+043E) + Latin "min"
        let input = "\u{0430}d\u{043E}min";
        let warnings = check_confusable(input);
        assert!(
            warnings.len() >= 2,
            "应至少有 2 个警告（Cyrillic 'а' 与 Cyrillic 'о'），实际: {}",
            warnings.len()
        );
        // 验证两个 Cyrillic 字符都被检测到
        let chars: Vec<char> = warnings.iter().map(|w| w.char).collect();
        assert!(chars.contains(&'\u{0430}'), "应检测到 Cyrillic 'а'");
        assert!(chars.contains(&'\u{043E}'), "应检测到 Cyrillic 'о'");
    }

    /// T083-6: 数字同形异义（Arabic-Indic Digit One U+0661 与 Latin Digit One U+0031）返回警告。
    ///
    /// Arabic-Indic '١' (U+0661) 视觉与 Latin '1' (U+0031) 相似，TR39 skeleton 算法将两者
    /// 均映射为 'l'（lowercase L），故 `confusable_with` 为 'l'。
    /// 注：Unicode 无 Cyrillic 数字 '1'；U+FF11 Fullwidth Digit One 不在 TR39 confusables 表中
    /// （skeleton 返回自身），故使用 Arabic-Indic Digit One 验证跨脚本数字同形异义检测。
    #[test]
    fn check_confusable_detects_mixed_digits() {
        // Arabic-Indic Digit One '١' (U+0661)
        let input = "v\u{0661}";
        let warnings = check_confusable(input);
        assert!(!warnings.is_empty(), "应检测到 Arabic-Indic '١' 可疑数字");
        let digit_warning = warnings
            .iter()
            .find(|w| w.char == '\u{0661}')
            .expect("应包含 Arabic-Indic '١' (U+0661) 的警告");
        // TR39 skeleton of U+0661 is 'l' (与 Latin '1' 的 skeleton 相同)
        assert_eq!(
            digit_warning.confusable_with, 'l',
            "Arabic-Indic '١' 的 skeleton 应为 'l'"
        );
    }
}
