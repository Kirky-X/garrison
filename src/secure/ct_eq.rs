// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 常量时间比较原语（CWE-208 防御）。
//!
//! 提供 `constant_time_eq` 函数，基于 `subtle::ConstantTimeEq` 实现字节级常量时间比较，
//! 防止逐元素短路比较引入的时序侧信道（攻击者可能通过响应时间逐字节推断密钥）。
//!
//! # 适用场景
//!
//! HMAC 签名链、OAuth2 PKCE code_challenge、API Key/token 哈希比对、HTTP Digest 签名、
//! 邮箱/短信验证码、备份码 SHA-256 比对等敏感比较；消费者清单以本列表为单一事实源。
//!
//! # 算法
//!
//! 与 `subtle::ConstantTimeEq` 等价：长度比较不 early return，字节比较遍历到 `max_len`
//! （短方 0 padding，循环次数与内容无关），用 `Choice` 的 `BitAnd`/`BitXor` 聚合避免分支短路。
//!
//! # 调用约定
//!
//! 调用前先校验输入长度（如 HMAC-SHA256 hex 应为 64 字节），异常长度直接失败，防超长输入放大成 CPU DoS。

use subtle::ConstantTimeEq;

/// 常量时间比较两个字节切片，防逐字节时序侧信道（CWE-208）。
///
/// 长度不等或字节不匹配均不 early return，循环照常执行到 `max_len`，长度与全部字节
/// 均相等才返回 `true`。调用方须先校验输入长度合法性（如固定长度签名），超长输入
/// 仍执行完整循环，需自行限制长度以防 DoS。
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

/// 去除单行中的注释（`//` 与 `///`/`//!` 起始），供源码扫描守卫使用。
///
/// 仅做行首裁剪（守卫目标标识符不会出现在行中注释尾部），不处理块注释。
#[cfg(test)]
fn strip_rust_comment(line: &str) -> &str {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        ""
    } else {
        line
    }
}

/// 递归收集目录下全部 `.rs` 源文件，返回 `(相对 src_root 的路径, 源码)` 列表。
///
/// 仅用 `std::fs` 实现（避免为测试引入 walkdir 新依赖），路径分隔符统一为 `/`。
#[cfg(test)]
fn collect_rs_sources(dir: &std::path::Path, src_root: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(collect_rs_sources(&path, src_root));
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(source) = std::fs::read_to_string(&path) {
                let rel = path
                    .strip_prefix(src_root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, source));
            }
        }
    }
    out
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

    // ADR-0003 统一原语守卫（决策 2：消除第二实现）：需常量时间比较的 feature 一律依赖 secure-ct-eq，禁止本地复制实现；
    // 锁定两点——src/ 下无同名第二实现，敏感 feature 在 Cargo.toml 声明 secure-ct-eq 且源码不直连 subtle（防实现漂移）。

    /// 全库常量时间比较统一原语守卫（ADR-0003 决策 2）。
    #[test]
    fn acc_adr0003_single_implementation_no_local_duplicates() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let src_root = format!("{manifest_dir}/src");
        let mut violations = Vec::new();
        for (rel, source) in collect_rs_sources(std::path::Path::new(&src_root), &src_root) {
            // ct_eq.rs 是原语本体，跳过；其余文件扫描第二实现
            if rel == "secure/ct_eq.rs" {
                continue;
            }
            for (idx, line) in source.lines().enumerate() {
                let code = strip_rust_comment(line);
                // 精确匹配「fn + 函数名 + 左括号」；`use` 导入、调用点与 `fn constant_time_eq_xxx` 测试名不构成实现。
                if code.contains("fn constant_time_eq(") {
                    violations.push(format!(
                        "src/{rel}:{}: 本地 constant_time_eq 第二实现（ADR-0003 决策 2 要求统一走 secure::ct_eq）",
                        idx + 1
                    ));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "ADR-0003 守卫：发现本地常量时间比较第二实现：\n{}",
            violations.join("\n")
        );
    }

    /// 敏感路径 feature 声明 + 源码 subtle 直连守卫（ADR-0003 决策 2/3）。
    #[test]
    fn acc_adr0003_sensitive_paths_depend_on_secure_ct_eq() {
        let manifest = include_str!("../../Cargo.toml");
        // ADR-0003 决策 2/3 适用路径对应的 feature（决策 3 清单五路径 + 验证码比对与 API Key 中间件两扩展路径，均已统一依赖 secure-ct-eq）
        const SENSITIVE_FEATURES: &[&str] = &[
            "protocol-apikey",
            "audit-log",
            "oauth2-server",
            "protocol-httpdigest",
            "secure-simple-token",
            "secure-sign",
            "web-csrf",
            "email-verification",
            "sms-rate-limit",
        ];
        for feature in SENSITIVE_FEATURES {
            let decl = format!("{feature} = [");
            assert!(
                manifest.contains(&decl),
                "ADR-0003 守卫：feature '{feature}' 未在 Cargo.toml 声明"
            );
            let line = manifest
                .lines()
                .find(|l| l.starts_with(&decl))
                .unwrap_or_else(|| panic!("feature '{feature}' 声明行缺失"));
            assert!(
                line.contains("secure-ct-eq"),
                "ADR-0003 决策 2 守卫：feature '{feature}' 必须依赖 secure-ct-eq，实际: {line}"
            );
        }

        // 敏感路径源码不得直连 subtle（统一走 secure::ct_eq）；白名单（相对 src/ 路径）为原语本身与
        // saml / oidc / qrlogin service（XML DigestValue / OIDC nonce 等定长哈希比较，非决策 3 清单路径）。
        const ALLOWED_SUBTLE_DIRECT: &[&str] = &[
            "secure/ct_eq.rs",
            "protocol/sso/saml.rs",
            "protocol/oauth2/oidc.rs",
            "protocol/qrlogin/service.rs",
        ];
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let src_root = format!("{manifest_dir}/src");
        let mut violations = Vec::new();
        for (rel, source) in collect_rs_sources(std::path::Path::new(&src_root), &src_root) {
            for (idx, line) in source.lines().enumerate() {
                let code = strip_rust_comment(line);
                if code.contains("subtle::ConstantTimeEq") || code.contains("subtle::Choice") {
                    let allowed = ALLOWED_SUBTLE_DIRECT.contains(&rel.as_str());
                    if !allowed {
                        violations.push(format!(
                            "src/{rel}:{}: 敏感路径 subtle 直连（ADR-0003 决策 2 要求走 secure::ct_eq）: {}",
                            idx + 1,
                            code.trim()
                        ));
                    }
                }
            }
        }
        assert!(
            violations.is_empty(),
            "ADR-0003 守卫：发现敏感路径 subtle 直连：\n{}",
            violations.join("\n")
        );
    }

    /// 与切片/`str` 相等语义等价：消费模块（验证码、哈希、签名比较）的可观测语义须与短路
    /// 比较完全一致；等价矩阵在本原语处单点维护，消费模块仅保留 smoke。
    #[test]
    fn matches_slice_equality_matrix() {
        let samples: [&[u8]; 10] = [
            b"", b"a", b"ab", b"abc", b"abcd", b"xyz", b"123456", b"12345", b"654321", b"abcdef",
        ];
        for a in samples {
            for b in samples {
                assert_eq!(
                    constant_time_eq(a, b),
                    a == b,
                    "constant_time_eq({:?}, {:?}) 应与切片相等语义一致",
                    String::from_utf8_lossy(a),
                    String::from_utf8_lossy(b)
                );
            }
        }
    }

    /// `str.as_bytes()` 视图同矩阵：验证码/哈希字符串比较场景的等价性。
    #[test]
    fn matches_str_equality_matrix() {
        let samples = [
            "", "1", "12", "123456", "12345", "654321", "000000", "abcdef",
        ];
        for a in samples {
            for b in samples {
                assert_eq!(
                    constant_time_eq(a.as_bytes(), b.as_bytes()),
                    a == b,
                    "constant_time_eq({a:?}, {b:?}) 应与 str 相等语义一致"
                );
            }
        }
    }
}
