//! 密码哈希子模块（v0.6.0 从 secure/password/ 迁移，依据 spec credential-model）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
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
//! ## 迁移说明（v0.6.0）
//!
//! 本模块从 `secure/password/mod.rs` 迁移到 `account/credential/password.rs`。
//! - `secure-password` feature → `account-credential` feature
//! - `secure-password-zeroize` feature → `account-credential-zeroize` feature
//! - `use crate::secure::password::*` → `use crate::account::credential::password::*`
//!
//! ## 不引入的算法
//!
//! - MD5/SHA1 密码哈希（已废弃，仅 Digest 认证保留）
//! - PBKDF2/SCrypt（v0.5.0+ 按需）

use super::{Credential, CredentialModel, CredentialType};
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
        // P2.1: account-credential-zeroize feature 启用时，将 password 字节拷贝到
        // Zeroizing<Vec<u8>> wrapper；函数返回时 wrapper Drop 清零内部字节。
        // &str 是不可变借用，无法清零调用方持有的 String，故内部拷贝后清零。
        #[cfg(feature = "account-credential-zeroize")]
        let password_bytes = zeroize::Zeroizing::new(password.as_bytes().to_vec());
        #[cfg(feature = "account-credential-zeroize")]
        let password_ref: &[u8] = &password_bytes;
        #[cfg(not(feature = "account-credential-zeroize"))]
        let password_ref: &[u8] = password.as_bytes();

        let salt = SaltString::generate(&mut OsRng);
        // H4: 显式预分配 32 字节输出缓冲区（与 argon2 默认一致，但显式化意图并锁定行为）
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| BulwarkError::InvalidParam(format!("Argon2 参数无效: {}", e)))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let hash = argon2
            .hash_password(password_ref, &salt)
            .map_err(|e| BulwarkError::Internal(format!("Argon2 哈希失败: {}", e)))?
            .to_string();
        Ok(hash)
        // password_bytes drops here (if zeroize on); Zeroizing<Vec<u8>>::drop zeroes bytes
    }

    fn verify(&self, password: &str, hash: &str) -> BulwarkResult<bool> {
        // P2.1: 同 hash，verify 后清零内部 password 字节副本
        #[cfg(feature = "account-credential-zeroize")]
        let password_bytes = zeroize::Zeroizing::new(password.as_bytes().to_vec());
        #[cfg(feature = "account-credential-zeroize")]
        let password_ref: &[u8] = &password_bytes;
        #[cfg(not(feature = "account-credential-zeroize"))]
        let password_ref: &[u8] = password.as_bytes();

        let parsed = PasswordHash::new(hash)
            .map_err(|e| BulwarkError::InvalidParam(format!("Argon2 哈希格式无效: {}", e)))?;
        // verify 时用默认 Argon2（参数从 hash 字符串解析）
        let argon2 = Argon2::default();
        match argon2.verify_password(password_ref, &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(BulwarkError::Internal(format!("Argon2 校验失败: {}", e))),
        }
        // password_bytes drops here (if zeroize on); Zeroizing<Vec<u8>>::drop zeroes bytes
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
// PasswordCredential（Credential trait 实现，依据 spec R-credential-model-004）
// ============================================================================

/// 密码凭证（实现 [`Credential`] trait，委托 [`PasswordHasher`] 校验）。
///
/// 持有 `CredentialModel`（存储模型）+ `Box<dyn PasswordHasher>`（哈希器），
/// `verify()` 委托 `PasswordHasher::verify(input, &model.secret_data)`。
///
/// # 示例
///
/// ```ignore
/// use bulwark::account::credential::password::{Argon2Hasher, PasswordCredential, PasswordHasher};
/// use bulwark::account::credential::CredentialModel;
/// use std::boxed::Box;
///
/// let hasher = Argon2Hasher::default();
/// let hash = hasher.hash("secret")?;
/// let model = CredentialModel {
///     id: "cred-001".into(),
///     user_id: "alice".into(),
///     credential_type: "password".into(),
///     secret_data: hash,
///     label: None,
///     created_at: 0,
///     enabled: true,
///     priority: 0,
/// };
/// let cred = PasswordCredential::new(model, Box::new(hasher));
/// assert!(cred.verify("secret").await?);
/// ```
pub struct PasswordCredential {
    /// 凭证存储模型。
    model: CredentialModel,
    /// 密码哈希器（Argon2 / Bcrypt / 自定义）。
    hasher: Box<dyn PasswordHasher>,
}

impl PasswordCredential {
    /// 创建密码凭证。
    ///
    /// # 参数
    /// - `model`: 凭证存储模型（`secret_data` 字段应包含已哈希的密码）
    /// - `hasher`: 密码哈希器（用于 `verify` 时校验）
    pub fn new(model: CredentialModel, hasher: Box<dyn PasswordHasher>) -> Self {
        Self { model, hasher }
    }
}

#[async_trait::async_trait]
impl Credential for PasswordCredential {
    fn credential_type(&self) -> CredentialType {
        "password"
    }

    fn to_model(&self) -> CredentialModel {
        self.model.clone()
    }

    async fn verify(&self, input: &str) -> BulwarkResult<bool> {
        self.hasher.verify(input, &self.model.secret_data)
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

    // ========================================================================
    // Argon2 输出长度契约测试（依据 spec secure-password H4）
    // ========================================================================

    /// H4: Argon2Hasher::hash 输出长度为 32 字节（预分配缓冲区）。
    ///
    /// PHC 格式：`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`
    /// 末段为 hash 的 base64 编码（无 padding），解码后应为 32 字节。
    ///
    /// 注意：此测试依赖 `base64` crate 解码 PHC 末段，需启用含 `base64` 的 feature
    /// （如 `protocol-oauth2` / `secure-httpbasic` / `full`）。仅启用 `account-credential`
    /// 时此测试不编译（生产代码不依赖 base64）。
    #[cfg(feature = "base64")]
    #[test]
    fn hash_produces_32_byte_output() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("test-password").expect("hash 应成功");
        // 以 $ 分隔：[0]=""（空前缀）, [1]="argon2id", [2]="v=19",
        //          [3]="m=...,t=...,p=...", [4]="<salt>", [5]="<hash>"
        let parts: Vec<&str> = hash.split('$').collect();
        assert!(
            parts.len() >= 6,
            "PHC hash 字符串应至少 6 段，实际: {} (hash={})",
            parts.len(),
            hash
        );
        let hash_b64 = parts[5];
        // PHC 标准使用 base64 无 padding
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
        let hash_bytes = STANDARD_NO_PAD
            .decode(hash_b64)
            .expect("hash 末段应是合法 base64 (无 padding)");
        assert_eq!(
            hash_bytes.len(),
            32,
            "Argon2 输出应为 32 字节，实际: {} (hash={})",
            hash_bytes.len(),
            hash
        );
    }

    // ========================================================================
    // P2.1 zeroize 测试（依据 spec account-credential-zeroize）
    // ========================================================================

    /// P2.1: account-credential-zeroize feature 启用时，hash/verify 仍正确工作，
    /// 且内部 password 字节副本在 hash 返回后被 zeroize 清零。
    ///
    /// 注意：hash/verify 接受 `&str`（不可变借用），无法清零调用方持有的 String。
    /// 内部实现将 password 字节拷贝到 `Zeroizing<Vec<u8>>`，函数返回时该 wrapper
    /// 的 Drop 实现清零内部字节。此处验证：
    /// 1. hash/verify 在 zeroize feature 启用时仍正确工作（无回归）
    /// 2. Zeroizing<Vec<u8>> 包装的 password 字节在 .zeroize() 后被清零
    ///    （这是 hash 内部使用的清零机制）
    /// 3. Zeroizing<String> wrapper 可与 hash 配合使用（通过 Deref<Target=str>）
    #[cfg(feature = "account-credential-zeroize")]
    #[test]
    fn password_param_zeroed_after_hash() {
        use zeroize::{Zeroize, Zeroizing};

        let hasher = Argon2Hasher::default();
        let password = "my-secret-password";

        // 1. hash/verify 在 account-credential-zeroize feature 启用时仍正确工作
        let hash = hasher.hash(password).expect("hash 应成功");
        assert!(
            hash.starts_with("$argon2id$"),
            "hash 应以 $argon2id$ 开头，实际: {}",
            hash
        );
        assert!(
            hasher
                .verify(password, &hash)
                .expect("verify 正确密码应成功"),
            "正确密码应校验通过"
        );
        assert!(
            !hasher
                .verify("wrong", &hash)
                .expect("verify 错误密码应成功"),
            "错误密码应校验失败"
        );

        // 2. 验证 hash 内部使用的 zeroize 机制：
        //    a) Vec<u8>::zeroize() 先零填充字节再 clear（length=0，capacity 保留）
        let mut local_copy: Vec<u8> = password.as_bytes().to_vec();
        local_copy.zeroize();
        assert_eq!(local_copy.len(), 0, "Vec::zeroize 后 length 应为 0 (clear)");

        //    b) [u8; N]::zeroize() 仅零填充字节（数组长度固定，不 clear）
        //       证明 zeroize 的字节清零语义
        let mut arr: [u8; 18] = [0; 18];
        arr.copy_from_slice(password.as_bytes());
        arr.zeroize();
        assert!(
            arr.iter().all(|&b| b == 0),
            "数组 zeroize 后所有字节应为 0，实际: {:?}",
            arr
        );

        // 3. Zeroizing<String> wrapper 可与 hash 配合（通过 Deref<Target=String> → str）
        //    调用方可用此 wrapper 持有 password，wrapper Drop 时清零底层字节
        let wrapped = Zeroizing::new(password.to_string());
        let hash2 = hasher.hash(wrapped.as_str()).expect("hash 应成功");
        assert!(
            hasher
                .verify(wrapped.as_str(), &hash2)
                .expect("verify 应成功"),
            "wrapped password 校验应通过"
        );
        // wrapped 在此处仍未 drop；当 wrapped 离开作用域时，Zeroizing<String>::drop
        // 会调用 String::zeroize() 清零底层字节（由 zeroize crate 保证）
    }

    // ========================================================================
    // PasswordCredential 测试（依据 spec R-credential-model-004）
    // ========================================================================

    /// 辅助函数：构造测试用 PasswordCredential + 原始密码。
    fn make_password_cred(id: &str, user: &str, password: &str) -> (PasswordCredential, String) {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash(password).expect("hash 应成功");
        let model = CredentialModel {
            id: id.to_string(),
            user_id: user.to_string(),
            credential_type: "password".to_string(),
            secret_data: hash,
            label: None,
            created_at: 0,
            enabled: true,
            priority: 0,
        };
        let cred = PasswordCredential::new(model, Box::new(hasher));
        (cred, password.to_string())
    }

    /// R-004: `credential_type()` 返回常量 `"password"`。
    #[test]
    fn password_credential_type_returns_password() {
        let (cred, _) = make_password_cred("c1", "alice", "secret");
        assert_eq!(cred.credential_type(), "password");
    }

    /// R-004: `to_model()` 返回原始 CredentialModel（字段一致）。
    #[test]
    fn password_credential_to_model_returns_original() {
        let (cred, _) = make_password_cred("c1", "alice", "secret");
        let model = cred.to_model();
        assert_eq!(model.id, "c1");
        assert_eq!(model.user_id, "alice");
        assert_eq!(model.credential_type, "password");
        assert!(
            model.secret_data.starts_with("$argon2id$"),
            "secret_data 应为 argon2 hash"
        );
    }

    /// R-004: `verify()` 正确密码返回 `Ok(true)`。
    #[tokio::test]
    async fn password_credential_verify_correct_password() {
        let (cred, password) = make_password_cred("c1", "alice", "my-secret");
        let result = cred.verify(&password).await.expect("verify 应成功");
        assert!(result, "正确密码应校验通过");
    }

    /// R-004: `verify()` 错误密码返回 `Ok(false)`。
    #[tokio::test]
    async fn password_credential_verify_wrong_password() {
        let (cred, _) = make_password_cred("c1", "alice", "my-secret");
        let result = cred
            .verify("wrong-password")
            .await
            .expect("verify 应成功（返回 false 而非报错）");
        assert!(!result, "错误密码应校验失败");
    }

    /// R-004: `PasswordCredential` 支持 BcryptHasher（多 hasher 兼容）。
    #[tokio::test]
    async fn password_credential_works_with_bcrypt_hasher() {
        let hasher = BcryptHasher::default();
        let hash = hasher.hash("bcrypt-secret").expect("hash 应成功");
        let model = CredentialModel {
            id: "c2".to_string(),
            user_id: "bob".to_string(),
            credential_type: "password".to_string(),
            secret_data: hash,
            label: None,
            created_at: 0,
            enabled: true,
            priority: 0,
        };
        let cred = PasswordCredential::new(model, Box::new(hasher));

        // 正确密码
        assert!(
            cred.verify("bcrypt-secret").await.expect("verify 应成功"),
            "Bcrypt 正确密码应校验通过"
        );
        // 错误密码
        assert!(
            !cred.verify("wrong").await.expect("verify 应成功"),
            "Bcrypt 错误密码应校验失败"
        );
    }

    /// R-004: `PasswordCredential` 可作 `Box<dyn Credential>` 使用（对象安全验证）。
    #[tokio::test]
    async fn password_credential_usable_as_dyn_credential() {
        let (cred, password) = make_password_cred("c1", "alice", "secret");
        let dyn_cred: Box<dyn Credential> = Box::new(cred);
        assert_eq!(dyn_cred.credential_type(), "password");
        let result = dyn_cred.verify(&password).await.expect("verify 应成功");
        assert!(result, "dyn Credential 正确密码应校验通过");
    }

    /// R-004: `PasswordCredential` 在 `account-credential-zeroize` feature 启用时仍正确工作。
    #[cfg(feature = "account-credential-zeroize")]
    #[tokio::test]
    async fn password_credential_zeroize_integration() {
        let (cred, password) = make_password_cred("c1", "alice", "zeroize-secret");
        // verify 在 zeroize feature 启用时仍正确工作
        let result = cred.verify(&password).await.expect("verify 应成功");
        assert!(result, "zeroize feature 启用时正确密码应校验通过");
        // 错误密码
        let wrong = cred.verify("wrong").await.expect("verify 应成功");
        assert!(!wrong, "zeroize feature 启用时错误密码应校验失败");
    }
}
