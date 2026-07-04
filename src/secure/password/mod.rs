//! 密码哈希子模块（0.4.2 新增，依据 spec secure-password）。
//!
//! 提供 `PasswordHasher` trait + `Argon2Hasher` / `BcryptHasher` 实现 + `PasswordVerifier` 自动识别。
//!
//! ## 设计
//!
//! - `PasswordHasher` trait 定义 `hash` / `verify` 抽象
//! - `Argon2Hasher` 使用 argon2 0.5 crate（Argon2id, m=19456, t=2, p=1）
//! - `BcryptHasher` 使用 bcrypt 0.15 crate（默认 cost=12）
//! - `PasswordVerifier` 根据 hash 前缀自动选择算法校验
//!
//! ## 不引入的算法
//!
//! - MD5/SHA1 密码哈希（已废弃，仅 Digest 认证保留）
//! - PBKDF2/SCrypt（v0.5.0+ 按需）

use crate::error::{BulwarkError, BulwarkResult};

// argon2::password_hash::PasswordHasher / PasswordVerifier 与本模块自定义 PasswordHasher 同名，
// 通过 `as _` 导入 trait 方法可用，但不引入名字，避免冲突。
use argon2::{
    password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand::rngs::OsRng;

// ============================================================================
// Trait 定义
// ============================================================================

/// 密码哈希器 trait（依据 spec secure-password R-001）。
///
/// 提供 `hash`（密码 → 哈希字符串）与 `verify`（密码 + 哈希 → 是否匹配）方法。
/// 实现必须为 `Send + Sync`（可在多线程环境共享）。
pub trait PasswordHasher: Send + Sync {
    /// 将明文密码哈希为字符串。
    ///
    /// # 参数
    /// - `password`: 明文密码。
    ///
    /// # 返回
    /// - `Ok(hash)`: 哈希字符串（含算法标识、盐、参数）。
    fn hash(&self, password: &str) -> BulwarkResult<String>;

    /// 校验明文密码与哈希是否匹配。
    ///
    /// # 参数
    /// - `password`: 明文密码。
    /// - `hash`: 哈希字符串（由 `hash` 方法生成）。
    ///
    /// # 返回
    /// - `Ok(true)`: 密码匹配。
    /// - `Ok(false)`: 密码不匹配。
    /// - `Err`: 哈希格式无效或校验失败。
    fn verify(&self, password: &str, hash: &str) -> BulwarkResult<bool>;
}

// ============================================================================
// Argon2Hasher 实现（依据 spec secure-password R-002）
// ============================================================================

/// Argon2id 密码哈希器（依据 spec secure-password R-002）。
///
/// 使用 argon2 0.5 crate，默认参数：Argon2id, m=19456 KiB, t=2, p=1。
/// 可通过 `with_params` 自定义参数。
pub struct Argon2Hasher {
    /// 内存成本（KiB），默认 19456（19 MiB）。
    m_cost: u32,
    /// 时间成本（迭代次数），默认 2。
    t_cost: u32,
    /// 并行度，默认 1。
    p_cost: u32,
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self {
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

impl Argon2Hasher {
    /// 创建默认参数的 Argon2Hasher（Argon2id, m=19456, t=2, p=1）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 自定义 Argon2 参数。
    ///
    /// # 参数
    /// - `m_cost`: 内存成本（KiB）。
    /// - `t_cost`: 时间成本（迭代次数）。
    /// - `p_cost`: 并行度。
    pub fn with_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
        }
    }
}

impl PasswordHasher for Argon2Hasher {
    fn hash(&self, password: &str) -> BulwarkResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, None)
            .map_err(|e| BulwarkError::InvalidParam(format!("Argon2 参数无效: {}", e)))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| BulwarkError::Internal(format!("Argon2 哈希失败: {}", e)))?
            .to_string();
        Ok(hash)
    }

    fn verify(&self, password: &str, hash: &str) -> BulwarkResult<bool> {
        let parsed = PasswordHash::new(hash)
            .map_err(|e| BulwarkError::InvalidParam(format!("Argon2 哈希格式无效: {}", e)))?;
        // verify 时用默认 Argon2（参数从 hash 字符串解析）
        let argon2 = Argon2::default();
        match argon2.verify_password(password.as_bytes(), &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(BulwarkError::Internal(format!("Argon2 校验失败: {}", e))),
        }
    }
}

// ============================================================================
// BcryptHasher 实现（依据 spec secure-password R-003）
// ============================================================================

/// Bcrypt 密码哈希器（依据 spec secure-password R-003）。
///
/// 使用 bcrypt 0.15 crate，默认 cost=12。
pub struct BcryptHasher {
    /// cost 参数（4-31），默认 12。
    cost: u32,
}

impl Default for BcryptHasher {
    fn default() -> Self {
        Self { cost: 12 }
    }
}

impl BcryptHasher {
    /// 创建默认 cost=12 的 BcryptHasher。
    pub fn new() -> Self {
        Self::default()
    }

    /// 自定义 cost 参数。
    ///
    /// # 参数
    /// - `cost`: cost 参数（4-31，建议 10-14）。
    pub fn with_cost(cost: u32) -> Self {
        Self { cost }
    }
}

impl PasswordHasher for BcryptHasher {
    fn hash(&self, password: &str) -> BulwarkResult<String> {
        bcrypt::hash(password, self.cost)
            .map_err(|e| BulwarkError::Internal(format!("Bcrypt 哈希失败: {}", e)))
    }

    fn verify(&self, password: &str, hash: &str) -> BulwarkResult<bool> {
        bcrypt::verify(password, hash)
            .map_err(|e| BulwarkError::InvalidParam(format!("Bcrypt 哈希格式无效: {}", e)))
    }
}

// ============================================================================
// PasswordVerifier 自动识别（依据 spec secure-password R-004）
// ============================================================================

/// 密码校验器，根据 hash 前缀自动选择算法校验（依据 spec secure-password R-004）。
///
/// - `$argon2id$` 前缀 → 委托 `Argon2Hasher`
/// - `$2b$` / `$2a$` / `$2y$` 前缀 → 委托 `BcryptHasher`
/// - 其他前缀 → 返回 `BulwarkError::InvalidParam`
pub struct PasswordVerifier;

impl PasswordVerifier {
    /// 校验密码，根据 hash 前缀自动选择算法。
    ///
    /// # 参数
    /// - `password`: 明文密码。
    /// - `hash`: 哈希字符串。
    ///
    /// # 返回
    /// - `Ok(true)`: 密码匹配。
    /// - `Ok(false)`: 密码不匹配。
    /// - `Err(BulwarkError::InvalidParam)`: 不支持的 hash 格式。
    pub fn verify(password: &str, hash: &str) -> BulwarkResult<bool> {
        if hash.starts_with("$argon2") {
            Argon2Hasher::default().verify(password, hash)
        } else if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
            BcryptHasher::default().verify(password, hash)
        } else {
            Err(BulwarkError::InvalidParam(format!(
                "不支持的 hash 格式: {}",
                &hash[..hash.len().min(10)]
            )))
        }
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // PasswordHasher trait 契约测试（依据 spec R-001）
    // ========================================================================

    /// R-001: PasswordHasher trait 为 Send + Sync（编译期检查）。
    #[test]
    fn password_hasher_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Argon2Hasher>();
        assert_send_sync::<BcryptHasher>();
        assert_send_sync::<PasswordVerifier>();
    }

    // ========================================================================
    // Argon2Hasher 测试（依据 spec R-002）
    // ========================================================================

    /// R-002: Argon2Hasher::default().hash("password") 返回 $argon2id$ 前缀字符串。
    #[test]
    fn argon2_hash_returns_argon2id_prefix() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("password").unwrap();
        assert!(
            hash.starts_with("$argon2id$"),
            "Argon2 哈希应以 $argon2id$ 开头，实际: {}",
            hash
        );
    }

    /// R-002: 相同密码两次 hash 产生不同结果（盐随机）。
    #[test]
    fn argon2_hash_same_password_produces_different_results() {
        let hasher = Argon2Hasher::default();
        let h1 = hasher.hash("password").unwrap();
        let h2 = hasher.hash("password").unwrap();
        assert_ne!(h1, h2, "相同密码两次 hash 应产生不同结果（盐随机）");
    }

    /// R-002: Argon2Hasher::verify 对正确密码返回 Ok(true)。
    #[test]
    fn argon2_verify_correct_password_returns_true() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("password").unwrap();
        let result = hasher.verify("password", &hash).unwrap();
        assert!(result, "正确密码应返回 Ok(true)");
    }

    /// R-002: Argon2Hasher::verify 对错误密码返回 Ok(false)。
    #[test]
    fn argon2_verify_wrong_password_returns_false() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("password").unwrap();
        let result = hasher.verify("wrong", &hash).unwrap();
        assert!(!result, "错误密码应返回 Ok(false)");
    }

    /// Argon2Hasher::with_params 自定义参数。
    #[test]
    fn argon2_with_params_customizes_costs() {
        let hasher = Argon2Hasher::with_params(8192, 1, 1);
        assert_eq!(hasher.m_cost, 8192);
        assert_eq!(hasher.t_cost, 1);
        assert_eq!(hasher.p_cost, 1);
        // 验证自定义参数下仍能正常 hash + verify
        let hash = hasher.hash("test").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(hasher.verify("test", &hash).unwrap());
    }

    // ========================================================================
    // BcryptHasher 测试（依据 spec R-003）
    // ========================================================================

    /// R-003: BcryptHasher::default().hash("password") 返回 $2b$ 前缀字符串。
    #[test]
    fn bcrypt_hash_returns_2b_prefix() {
        let hasher = BcryptHasher::default();
        let hash = hasher.hash("password").unwrap();
        assert!(
            hash.starts_with("$2b$"),
            "Bcrypt 哈希应以 $2b$ 开头，实际: {}",
            hash
        );
    }

    /// R-003: BcryptHasher::verify 对正确密码返回 Ok(true)。
    #[test]
    fn bcrypt_verify_correct_password_returns_true() {
        let hasher = BcryptHasher::default();
        let hash = hasher.hash("password").unwrap();
        let result = hasher.verify("password", &hash).unwrap();
        assert!(result, "正确密码应返回 Ok(true)");
    }

    /// R-003: BcryptHasher::verify 对错误密码返回 Ok(false)。
    #[test]
    fn bcrypt_verify_wrong_password_returns_false() {
        let hasher = BcryptHasher::default();
        let hash = hasher.hash("password").unwrap();
        let result = hasher.verify("wrong", &hash).unwrap();
        assert!(!result, "错误密码应返回 Ok(false)");
    }

    /// R-003: BcryptHasher::verify 识别 $2a$ 格式（兼容旧 bcrypt）。
    #[test]
    fn bcrypt_verify_recognizes_2a_format() {
        let hasher = BcryptHasher::default();
        // 先生成 $2b$ 哈希，然后把 $2b$ 改成 $2a$ 验证兼容性
        let hash = hasher.hash("password").unwrap();
        let hash_2a = hash.replacen("$2b$", "$2a$", 1);
        let result = hasher.verify("password", &hash_2a).unwrap();
        assert!(result, "BcryptHasher 应识别 $2a$ 格式");
    }

    /// R-003: BcryptHasher::verify 识别 $2y$ 格式（兼容旧 bcrypt）。
    #[test]
    fn bcrypt_verify_recognizes_2y_format() {
        let hasher = BcryptHasher::default();
        let hash = hasher.hash("password").unwrap();
        let hash_2y = hash.replacen("$2b$", "$2y$", 1);
        let result = hasher.verify("password", &hash_2y).unwrap();
        assert!(result, "BcryptHasher 应识别 $2y$ 格式");
    }

    /// BcryptHasher::with_cost 自定义 cost。
    #[test]
    fn bcrypt_with_cost_customizes_cost() {
        let hasher = BcryptHasher::with_cost(4);
        assert_eq!(hasher.cost, 4);
        let hash = hasher.hash("test").unwrap();
        assert!(hash.starts_with("$2b$"));
        assert!(hasher.verify("test", &hash).unwrap());
    }

    // ========================================================================
    // PasswordVerifier 自动识别测试（依据 spec R-004）
    // ========================================================================

    /// R-004: PasswordVerifier::verify 委托 Argon2Hasher（$argon2id$ 前缀）。
    #[test]
    fn password_verifier_delegates_to_argon2() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("password").unwrap();
        let result = PasswordVerifier::verify("password", &hash).unwrap();
        assert!(result, "PasswordVerifier 应委托 Argon2Hasher 校验正确密码");
        let wrong = PasswordVerifier::verify("wrong", &hash).unwrap();
        assert!(!wrong, "PasswordVerifier 应委托 Argon2Hasher 校验错误密码");
    }

    /// R-004: PasswordVerifier::verify 委托 BcryptHasher（$2b$ 前缀）。
    #[test]
    fn password_verifier_delegates_to_bcrypt() {
        let hasher = BcryptHasher::default();
        let hash = hasher.hash("password").unwrap();
        let result = PasswordVerifier::verify("password", &hash).unwrap();
        assert!(result, "PasswordVerifier 应委托 BcryptHasher 校验正确密码");
        let wrong = PasswordVerifier::verify("wrong", &hash).unwrap();
        assert!(!wrong, "PasswordVerifier 应委托 BcryptHasher 校验错误密码");
    }

    /// R-004: PasswordVerifier::verify 不支持的 hash 格式返回 InvalidParam。
    #[test]
    fn password_verifier_unsupported_format_returns_invalid_param() {
        let result = PasswordVerifier::verify("password", "$unknown$hash");
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "不支持的 hash 格式应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// R-004: PasswordVerifier::verify 识别 $2a$ 前缀（Bcrypt 兼容）。
    #[test]
    fn password_verifier_delegates_to_bcrypt_2a_format() {
        let hasher = BcryptHasher::default();
        let hash = hasher.hash("password").unwrap();
        let hash_2a = hash.replacen("$2b$", "$2a$", 1);
        let result = PasswordVerifier::verify("password", &hash_2a).unwrap();
        assert!(result, "PasswordVerifier 应识别 $2a$ 格式");
    }
}
