// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 常量时间比较原语（CWE-208 防御）。
//!
//! 提供 `constant_time_eq` 函数，基于 `subtle::ConstantTimeEq` 实现字节级常量时间比较，
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

    // ====================================================================
    // ADR-0003 统一原语守卫（决策 2：消除第二实现）
    //
    // ADR-0003 决策 2 要求：所有需要常量时间比较的 feature 依赖 secure-ct-eq，
    // 禁止各模块复制本地实现；决策 3 列出适用路径（OAuth2 PKCE、HTTP Digest
    // response、API Key secret、审计链、SimpleTokenStyle HMAC）。
    //
    // 2026-10 落地：protocol-apikey / audit-log / oauth2-server /
    // protocol-httpdigest / secure-simple-token / secure-sign / web-csrf /
    // email-verification / sms-rate-limit 九条路径已全部收敛到本模块
    // （敏感路径上的 subtle 直连仅剩 secure-ct-eq 本身、定长非密钥比较的
    // protocol-saml / protocol-oidc / protocol-qrlogin）。
    // 本守卫以源码扫描锁定两点，防止未来实现漂移（ADR Context 所述风险）：
    //   1. src/ 下不再出现同名本地 constant_time_eq 第二实现；
    //   2. 上述九 feature 在 Cargo.toml 中均声明依赖 secure-ct-eq（而非 dep:subtle 直连），
    //      且敏感路径源码无 `use subtle::ConstantTimeEq` 直连。
    // ====================================================================

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
                // 函数定义 `fn constant_time_eq(` / `pub(...) fn constant_time_eq(`：第二实现。
                // 精确匹配「fn + 函数名 + 左括号」——`use` 导入、`crate::secure::ct_eq::
                // constant_time_eq(` 调用点与 `fn constant_time_eq_xxx` 测试名不构成实现。
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
        // ADR-0003 决策 2/3 适用路径对应的 feature（决策 3 清单五路径 + 验证码
        // 比对与 API Key 中间件两扩展路径；均已统一依赖 secure-ct-eq）
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

        // 敏感路径源码不得直连 subtle（统一走 secure::ct_eq）。
        // 允许白名单（相对 src/ 的路径；与本 ADR 无关或定长非密钥比较）：
        // secure/ct_eq.rs（原语本身）、saml / oidc / qrlogin service（XML
        // DigestValue / OIDC nonce 等定长哈希比较，非 ADR-0003 决策 3 清单路径）。
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
