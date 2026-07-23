//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 常量时间比较原语（CWE-208 防御）。
//!
//! 提供 [`constant_time_eq`] 函数，基于 `subtle::ConstantTimeEq` 实现字节级常量时间比较，
//! 防止逐元素短路比较引入的时序侧信道（攻击者可能通过响应时间逐字节推断密钥）。
//!
//! # 适用场景
//!
//! - HMAC 签名链验证（`listener::audit::AuditLogListener::verify_signature_chain`）
//! - OAuth2 PKCE code_challenge 校验（`oauth2_server::authorize::verify_pkce`）
//! - API Key / token 哈希比对
//!
//! # 算法
//!
//! 与 `subtle::ConstantTimeEq` 等价：
//! - 长度比较不 early return（`len_eq = a.len().ct_eq(&b.len())`）
//! - 字节比较遍历到 `max_len`，短方用 0 padding（无论内容是否匹配都做同样多次循环）
//! - 最终用 `Choice` 的 `BitAnd` 与 `BitXor` 聚合，避免分支短路
//!
//! # 调用约定
//!
//! 调用方应在调用本函数前先校验输入长度（如 HMAC-SHA256 hex 应为 64 字节），
//! 异常长度直接返回失败，避免被超长输入放大成 CPU DoS。

use subtle::ConstantTimeEq;

/// 常量时间比较两个字节切片，防止逐字节时序侧信道（CWE-208）。
///
/// 长度比较与字节比较均为常量时间：
/// - 长度不等 → 返回 `false`，但循环仍执行到 `max_len`，与长度相等时的执行时间近似
/// - 字节不匹配 → 不 early return，继续循环到 `max_len`
///
/// # 参数
/// - `a`, `b`: 待比较的字节切片
///
/// # 返回
/// - 长度与全部字节均相等 → `true`
/// - 否则 → `false`
///
/// # 注意
///
/// 调用方应在调用前校验输入长度的合法性（如固定长度签名）。
/// 对超长输入本函数仍会执行完整循环，调用方需自行限制长度以防 DoS。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_eq = (a.len() as u64).ct_eq(&(b.len() as u64));
    let max_len = a.len().max(b.len());
    let mut byte_eq = subtle::Choice::from(1u8);
    for i in 0..max_len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        byte_eq &= x.ct_eq(&y);
    }
    (len_eq & byte_eq).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_slices_return_true() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(&[0u8; 32], &[0u8; 32]));
    }

    #[test]
    fn different_slices_return_false() {
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hellp"));
    }

    #[test]
    fn different_lengths_return_false() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn long_inputs_no_panic() {
        let a = vec![0u8; 1024];
        let b = vec![0u8; 1024];
        assert!(constant_time_eq(&a, &b));
        let mut c = b.clone();
        c[1023] = 1;
        assert!(!constant_time_eq(&a, &c));
    }
}
