//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 邀请码生成与输入规范化。
//!
//! 码字符集采用去歧义子集（不含 `0/O`、`1/I/L`），人类可抄写、可口头转述；
//! 存储与匹配统一使用规范化后的无连字符大写形态。

use crate::error::{GarrisonError, GarrisonResult};
use rand::rngs::OsRng;
use rand::Rng;

/// 码字符集：32 个去歧义大写字母数字（排除 `0/O`、`1/I/L`）。
pub const CHARSET: &str = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// 随机段长度（不含连字符）。
const CODE_LEN: usize = 8;

/// 生成形如 `XXXX-XXXX` 的随机邀请码（字符取自去歧义字符集）。
///
/// 使用 `OsRng`（操作系统 CSPRNG）：邀请码是凭证性质，随机源必须不可预测。
pub fn generate() -> String {
    let mut rng = OsRng;
    let bytes: Vec<u8> = (0..CODE_LEN)
        .map(|_| CHARSET.as_bytes()[rng.gen_range(0..CHARSET.len())])
        .collect();
    let body = String::from_utf8(bytes).expect("字符集为纯 ASCII");
    format!("{}-{}", &body[..4], &body[4..])
}

/// 规范化用户输入的邀请码：trim、大写、移除连字符，并逐字符校验字符集。
///
/// 返回规范化后的无连字符大写形态（与存储键一致）。
///
/// # 错误
/// - `GarrisonError::InvalidParam`: 空输入、超长（规范化后 > 32 字符）或含字符集之外字符。
pub fn normalize(input: &str) -> GarrisonResult<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(GarrisonError::InvalidParam(
            "invitation-code-invalid::".to_string(),
        ));
    }
    let upper = trimmed.to_ascii_uppercase();
    let normalized: String = upper.chars().filter(|c| *c != '-').collect();
    if normalized.is_empty() || normalized.len() > 32 {
        return Err(GarrisonError::InvalidParam(
            "invitation-code-invalid::".to_string(),
        ));
    }
    if let Some(bad) = normalized.chars().find(|c| !CHARSET.contains(*c)) {
        return Err(GarrisonError::InvalidParam(format!(
            "invitation-code-invalid::{}",
            bad
        )));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charset_has_31_unambiguous_chars() {
        // 36 个字母数字排除 0/O/1/I/L 共 5 个歧义字符
        assert_eq!(CHARSET.len(), 31);
        for bad in ['0', 'O', '1', 'I', 'L'] {
            assert!(!CHARSET.contains(bad), "字符集不应含歧义字符 {bad}");
        }
    }
}
