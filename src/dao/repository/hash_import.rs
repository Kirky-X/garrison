// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 导入哈希校验门（自 `repository/mod.rs` 迁出）。
//!
//! mod 接口隔离收口：常量、参数解析与校验门实现于此，
//! 公共路径经 `repository::{validate_imported_hash, ARGON2_IMPORT_*}`
//! re-export 保持不变。

use crate::error::{GarrisonError, GarrisonResult};

// ============================================================================
// 导入哈希参数防御上限（防单次登录 OOM / CPU DoS）
// ============================================================================

/// 导入密码哈希的 Argon2 内存成本上限（KiB，1 GiB）。
///
/// 防御出处（对齐 zitadel passwap `ValidateEncodedHash` 的防御意图）：导入的
/// 哈希是**不可信输入**，PHC 参数自描述——无上限的恶意串（如 `m=17179869176`）
/// 会让单次登录 verify 申请巨量内存（OOM）或巨量迭代（CPU 耗尽）。上限取
/// 常规登录档位（默认 m=19456 KiB）之上的宽裕值：覆盖合法迁移来源，拒绝
/// 资源攻击载荷。
pub const ARGON2_IMPORT_MAX_M_COST: u32 = 1_048_576;

/// 导入密码哈希的 Argon2 迭代次数上限（防御出处同 [`ARGON2_IMPORT_MAX_M_COST`]）。
pub const ARGON2_IMPORT_MAX_T: u32 = 10;

/// 导入密码哈希的 Argon2 并行度上限（防御出处同 [`ARGON2_IMPORT_MAX_M_COST`]）。
pub const ARGON2_IMPORT_MAX_P: u32 = 4;

/// 导入密码哈希的 bcrypt cost 上限（防御出处同 [`ARGON2_IMPORT_MAX_M_COST`]）。
pub const BCRYPT_IMPORT_MAX_COST: u32 = 15;

/// 从 PHC 串提取 Argon2 参数段 `(m_cost, t_cost, p_cost)`。
///
/// 遍历 `$` 分段，找到首个同时含 `m=`/`t=`/`p=` 三键的段（跳过版本段、盐段、
/// hash 段——base64 无 padding，不含 `=`，不会误配）。缺任一键返回 `None`。
fn parse_argon2_import_params(hash: &str) -> Option<(u32, u32, u32)> {
    for segment in hash.split('$') {
        let mut m = None;
        let mut t = None;
        let mut p = None;
        for kv in segment.split(',') {
            if let Some((key, value)) = kv.split_once('=') {
                match key {
                    "m" => m = value.parse().ok(),
                    "t" => t = value.parse().ok(),
                    "p" => p = value.parse().ok(),
                    _ => {},
                }
            }
        }
        if let (Some(m), Some(t), Some(p)) = (m, t, p) {
            return Some((m, t, p));
        }
    }
    None
}

/// 校验外部导入的密码哈希：格式白名单 + 参数上限（防御门，出处见常量文档）。
///
/// 全部凭据导入/写入入口（`UserRepository::create` / `update` 的
/// `password_hash`、password 类型 credential 的写路径）必须先过本门。
///
/// # 白名单
///
/// 仅接受 `$argon2id$` / `$2b$` / `$2a$` / `$2y$` 前缀：argon2i/argon2d 已被
/// argon2id 取代，scrypt 等其他算法超出本框架 verify 能力——导入即不可验证，
/// 直接拒绝。
///
/// # Errors
///
/// 返回 [`GarrisonError::InvalidParam`]：白名单外前缀、Argon2 参数段缺失或
/// 不全、bcrypt cost 段缺失或非数字、任一参数超上限。整体拒绝，不静默降级。
pub fn validate_imported_hash(hash: &str) -> GarrisonResult<()> {
    if hash.starts_with("$argon2id$") {
        let (m_cost, t_cost, p_cost) = parse_argon2_import_params(hash).ok_or_else(|| {
            GarrisonError::InvalidParam(
                "import-hash-argon2-format::params-segment-missing-or-incomplete".to_string(),
            )
        })?;
        if m_cost > ARGON2_IMPORT_MAX_M_COST {
            return Err(GarrisonError::InvalidParam(format!(
                "import-hash-argon2-m-cost::{}>{}",
                m_cost, ARGON2_IMPORT_MAX_M_COST
            )));
        }
        if t_cost > ARGON2_IMPORT_MAX_T {
            return Err(GarrisonError::InvalidParam(format!(
                "import-hash-argon2-t-cost::{}>{}",
                t_cost, ARGON2_IMPORT_MAX_T
            )));
        }
        if p_cost > ARGON2_IMPORT_MAX_P {
            return Err(GarrisonError::InvalidParam(format!(
                "import-hash-argon2-p-cost::{}>{}",
                p_cost, ARGON2_IMPORT_MAX_P
            )));
        }
        return Ok(());
    }
    if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
        let cost = hash
            .split('$')
            .nth(2)
            .and_then(|cost| cost.parse::<u32>().ok())
            .ok_or_else(|| {
                GarrisonError::InvalidParam(
                    "import-hash-bcrypt-format::cost-segment-missing-or-invalid".to_string(),
                )
            })?;
        if cost > BCRYPT_IMPORT_MAX_COST {
            return Err(GarrisonError::InvalidParam(format!(
                "import-hash-bcrypt-cost::{}>{}",
                cost, BCRYPT_IMPORT_MAX_COST
            )));
        }
        return Ok(());
    }
    Err(GarrisonError::InvalidParam(format!(
        "import-hash-unsupported::<{}>",
        hash.get(..10).unwrap_or(hash)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // 导入哈希校验门
    // ========================================================================

    /// 上限常量值锁定：Argon2 m ≤ 1 GiB / t ≤ 10 / p ≤ 4，bcrypt cost ≤ 15
    /// （防单次登录 OOM / CPU DoS 的防御基线）。
    #[test]
    fn imported_hash_limit_constants_match_defense_baseline() {
        assert_eq!(ARGON2_IMPORT_MAX_M_COST, 1_048_576);
        assert_eq!(ARGON2_IMPORT_MAX_T, 10);
        assert_eq!(ARGON2_IMPORT_MAX_P, 4);
        assert_eq!(BCRYPT_IMPORT_MAX_COST, 15);
    }

    /// 越界参数：m/t/p 各超上限、bcrypt cost 超上限 → Err，错误含具体阶段标识
    /// （显性拒绝，不静默放行或截断）。
    #[test]
    fn imported_hash_rejects_out_of_range_params() {
        let m_over = "$argon2id$v=19$m=2097152,t=2,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg";
        match validate_imported_hash(m_over) {
            Err(GarrisonError::InvalidParam(msg)) => assert!(
                msg.contains("import-hash-argon2-m-cost"),
                "m 超上限错误应含 import-hash-argon2-m-cost，实际: {}",
                msg
            ),
            other => panic!("m 超上限应返回 InvalidParam，实际: {:?}", other.map(|_| ())),
        }
        let t_over = "$argon2id$v=19$m=19456,t=11,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg";
        match validate_imported_hash(t_over) {
            Err(GarrisonError::InvalidParam(msg)) => assert!(
                msg.contains("import-hash-argon2-t-cost"),
                "t 超上限错误应含 import-hash-argon2-t-cost，实际: {}",
                msg
            ),
            other => panic!("t 超上限应返回 InvalidParam，实际: {:?}", other.map(|_| ())),
        }
        let p_over = "$argon2id$v=19$m=19456,t=2,p=5$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg";
        match validate_imported_hash(p_over) {
            Err(GarrisonError::InvalidParam(msg)) => assert!(
                msg.contains("import-hash-argon2-p-cost"),
                "p 超上限错误应含 import-hash-argon2-p-cost，实际: {}",
                msg
            ),
            other => panic!("p 超上限应返回 InvalidParam，实际: {:?}", other.map(|_| ())),
        }
        // nosemgrep: generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash —— validate_imported_hash 超限测试的 bcrypt 形状夹具（非真实凭证）
        let bcrypt_over = "$2b$16$012345678901234567890123456789012345678901234567890123456";
        match validate_imported_hash(bcrypt_over) {
            Err(GarrisonError::InvalidParam(msg)) => assert!(
                msg.contains("import-hash-bcrypt-cost"),
                "bcrypt cost 超上限错误应含 import-hash-bcrypt-cost，实际: {}",
                msg
            ),
            other => panic!(
                "bcrypt cost 超上限应返回 InvalidParam，实际: {:?}",
                other.map(|_| ())
            ),
        }
    }

    /// 边界值：恰好等于上限 → Ok（不误杀合法迁移来源）。
    #[test]
    fn imported_hash_accepts_boundary_values() {
        let at_limit = "$argon2id$v=19$m=1048576,t=10,p=4$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg";
        assert!(
            validate_imported_hash(at_limit).is_ok(),
            "m=1GiB/t=10/p=4 恰在边界应放行"
        );
        // nosemgrep: generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash —— validate_imported_hash 边界值测试的 bcrypt 形状夹具（非真实凭证）
        let bcrypt_at_limit = "$2b$15$012345678901234567890123456789012345678901234567890123456";
        assert!(
            validate_imported_hash(bcrypt_at_limit).is_ok(),
            "bcrypt cost=15 恰在边界应放行"
        );
    }

    /// 白名单外前缀：argon2i/argon2d、scrypt、空串、乱串 → Err（仅四个白名单
    /// 前缀可导入）。
    #[test]
    fn imported_hash_rejects_non_whitelisted_prefixes() {
        let rejected = [
            "$argon2i$v=19$m=19456,t=2,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg",
            "$argon2d$v=19$m=19456,t=2,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg",
            "$scrypt$ln=16,r=8,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg",
            "$argon2idX$v=19$m=19456,t=2,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg",
            "not-a-hash",
            "",
        ];
        for bad in rejected {
            assert!(
                matches!(
                    validate_imported_hash(bad),
                    Err(GarrisonError::InvalidParam(_))
                ),
                "白名单外 {:?} 应返回 InvalidParam",
                bad
            );
        }
    }

    /// 白名单内常见来源：默认档位 argon2id 与三种 bcrypt 前缀变体 → Ok。
    #[test]
    fn imported_hash_accepts_whitelisted_formats() {
        let argon2id = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg";
        assert!(validate_imported_hash(argon2id).is_ok(), "默认档位应放行");
        for prefix in ["$2b$", "$2a$", "$2y$"] {
            let hash = format!(
                "{}12$012345678901234567890123456789012345678901234567890123456",
                prefix
            );
            assert!(
                validate_imported_hash(&hash).is_ok(),
                "{} 前缀 cost=12 应放行",
                prefix
            );
        }
    }

    /// 畸形参数段：argon2id 缺参数段 / 参数不全、bcrypt 缺 cost 段 → Err
    /// （无法确认参数上限即拒绝，fail-closed）。
    #[test]
    fn imported_hash_rejects_unparseable_params() {
        let missing_params = "$argon2id$v=19$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg";
        match validate_imported_hash(missing_params) {
            Err(GarrisonError::InvalidParam(msg)) => assert!(
                msg.contains("import-hash-argon2-format"),
                "缺参数段错误应含 import-hash-argon2-format，实际: {}",
                msg
            ),
            other => panic!("缺参数段应返回 InvalidParam，实际: {:?}", other.map(|_| ())),
        }
        let partial_params = "$argon2id$m=19456,t=2$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg";
        assert!(
            matches!(
                validate_imported_hash(partial_params),
                Err(GarrisonError::InvalidParam(_))
            ),
            "参数不全应返回 InvalidParam"
        );
        let bcrypt_no_cost = "$2b$rest-of-hash";
        match validate_imported_hash(bcrypt_no_cost) {
            Err(GarrisonError::InvalidParam(msg)) => assert!(
                msg.contains("import-hash-bcrypt-format"),
                "缺 cost 段错误应含 import-hash-bcrypt-format，实际: {}",
                msg
            ),
            other => panic!(
                "缺 cost 段应返回 InvalidParam，实际: {:?}",
                other.map(|_| ())
            ),
        }
        let bcrypt_bad_cost = "$2b$xx$012345678901234567890123456789012345678901234567890123456";
        assert!(
            matches!(
                validate_imported_hash(bcrypt_bad_cost),
                Err(GarrisonError::InvalidParam(_))
            ),
            "cost 段非数字应返回 InvalidParam"
        );
    }
}
