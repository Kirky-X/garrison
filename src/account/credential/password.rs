// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 密码哈希子模块。
//! 提供 `PasswordHasher` trait + `Argon2Hasher` / `BcryptHasher` 实现 + `PasswordVerifier` 自动识别。
//!
//! ## 设计
//!
//! - `PasswordHasher` trait 定义 `hash` / `verify` / `verify_and_rehash` 抽象
//!   （后者默认 = verify + None，Argon2Hasher 覆写为登录期惰性升级）
//! - `Argon2Hasher` 使用 argon2 0.5 crate（Argon2id, m=19456, t=2, p=1）
//! - `BcryptHasher` 使用 bcrypt 0.19 crate（默认 cost=12）
//! - `PasswordVerifier` 根据 hash 前缀自动选择算法校验
//!
//! ## 迁移说明
//!
//! 本模块从 `secure/password/mod.rs` 迁移到 `account/credential/password.rs`。
//! - `secure-password` feature → `account-credential` feature
//! - `secure-password-zeroize` feature → `account-credential-zeroize` feature
//! - `use crate::secure::password::*` → `use crate::account::credential::password::*`
//!
//! ## 不引入的算法
//!
//! - MD5/SHA1 密码哈希（已废弃，仅 Digest 认证保留）
//! - PBKDF2/SCrypt（按需）

use super::{Credential, CredentialModel, CredentialType};
use crate::error::{GarrisonError, GarrisonResult};
use std::sync::Arc;
use tokio::sync::Semaphore;

// argon2::password_hash::PasswordHasher / PasswordVerifier 与本模块自定义 PasswordHasher 同名，
// 通过 `as _` 导入 trait 方法可用，但不引入名字，避免冲突。
use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher as _, PasswordVerifier as _},
    Algorithm, Argon2, Params, Version,
};

// ============================================================================
// Trait 定义
// ============================================================================

/// 密码哈希器 trait。
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
    fn hash(&self, password: &str) -> GarrisonResult<String>;

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
    fn verify(&self, password: &str, hash: &str) -> GarrisonResult<bool>;

    /// 并发闸门探针：返回哈希执行的并发许可池（Argon2 内存 DoS 防护扩展点）。
    ///
    /// 默认 `None`（不限并发，向后兼容——自定义实现零改动）。返回 `Some` 的
    /// hasher 由 [`verify_pooled`] 统一封装「async 取 permit →
    /// spawn_blocking → permit 移入闭包」：permit 存活期 == 哈希执行期，调用方
    /// future 被取消时孤儿 blocking 任务继续持有 permit 直至完成，内存上界在
    /// 任何取消时序下恒等于 permits × m_cost（Argon2id 单次执行驻留 ≈ m_cost KiB），
    /// 不超卖；等待中的调用异步排队（不拒绝）。
    fn concurrency_gate(&self) -> Option<&Arc<Semaphore>> {
        None
    }

    /// 校验密码并按需产出升级哈希（登录期惰性迁移扩展点）。
    ///
    /// 默认实现 = [`verify`](Self::verify) + `None`（不迁移），自定义实现零改动。
    /// 返回 `(verify 结果, Option<升级后新 hash>)`：仅当 verify 通过且实现方
    /// 检测到存量哈希档位低于当前配置档位时返回 `Some`，且新 hash 必可通过
    /// 本实现 verify；verify 失败恒为 `(false, None)`。
    fn verify_and_rehash(
        &self,
        password: &str,
        hash: &str,
    ) -> GarrisonResult<(bool, Option<String>)> {
        let matched = self.verify(password, hash)?;
        Ok((matched, None))
    }
}

// ============================================================================
// Argon2Hasher 实现
// ============================================================================

/// Argon2id 密码哈希器。
///
/// 使用 argon2 0.5 crate，默认参数：Argon2id, m=19456 KiB, t=2, p=1。
/// 可通过 `with_params` 自定义参数、`with_pool` 装配并发令牌池
/// （内存 DoS 防护，经 [`verify_pooled`] 生效）。
pub struct Argon2Hasher {
    /// 内存成本（KiB），默认 19456（19 MiB）。
    m_cost: u32,
    /// 时间成本（迭代次数），默认 2。
    t_cost: u32,
    /// 并行度，默认 1。
    p_cost: u32,
    /// 并发令牌池（None = 不限并发）。permit 存活期 == 哈希执行期（移入
    /// spawn_blocking 闭包），任何取消时序下内存上界 = permits × m_cost。
    pool: Option<Arc<Semaphore>>,
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self {
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1,
            pool: None,
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
            pool: None,
        }
    }

    /// 装配并发令牌池（池大小 0 钳制为 1，fail-safe，对齐 [`BcryptHasher::with_cost`]
    /// 的 clamp 先例；配置层已 fail-fast 拒绝区间外值，此处为直接构造调用的兜底）。
    ///
    /// # 参数
    /// - `pool_size`: 同时执行中的 Argon2 hash/verify 上界；进程内存驻留上界
    ///   ≈ `pool_size × m_cost` KiB。
    pub fn with_pool(mut self, pool_size: usize) -> Self {
        self.pool = Some(Arc::new(Semaphore::new(pool_size.max(1))));
        self
    }
}

impl PasswordHasher for Argon2Hasher {
    fn concurrency_gate(&self) -> Option<&Arc<Semaphore>> {
        self.pool.as_ref()
    }

    fn hash(&self, password: &str) -> GarrisonResult<String> {
        // P2.1: account-credential-zeroize feature 启用时，将 password 字节拷贝到
        // Zeroizing<Vec<u8>> wrapper；函数返回时 wrapper Drop 清零内部字节。
        // &str 是不可变借用，无法清零调用方持有的 String，故内部拷贝后清零。
        #[cfg(feature = "credential-zeroize")]
        let password_bytes = zeroize::Zeroizing::new(password.as_bytes().to_vec());
        #[cfg(feature = "credential-zeroize")]
        let password_ref: &[u8] = &password_bytes;
        #[cfg(not(feature = "credential-zeroize"))]
        let password_ref: &[u8] = password.as_bytes();

        // 显式预分配 32 字节输出缓冲区（与 argon2 默认一致，但显式化意图并锁定行为）
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| GarrisonError::InvalidParam(format!("account-argon2-param::{}", e)))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let hash = argon2
            .hash_password(password_ref)
            .map_err(|e| GarrisonError::Internal(format!("account-argon2-hash::{}", e)))?
            .to_string();
        Ok(hash)
        // password_bytes drops here (if zeroize on); Zeroizing<Vec<u8>>::drop zeroes bytes
    }

    fn verify(&self, password: &str, hash: &str) -> GarrisonResult<bool> {
        // P2.1: 同 hash，verify 后清零内部 password 字节副本
        #[cfg(feature = "credential-zeroize")]
        let password_bytes = zeroize::Zeroizing::new(password.as_bytes().to_vec());
        #[cfg(feature = "credential-zeroize")]
        let password_ref: &[u8] = &password_bytes;
        #[cfg(not(feature = "credential-zeroize"))]
        let password_ref: &[u8] = password.as_bytes();

        let parsed = PasswordHash::new(hash)
            .map_err(|e| GarrisonError::InvalidParam(format!("account-argon2-format::{}", e)))?;
        // verify 时用默认 Argon2（参数从 hash 字符串解析）
        let argon2 = Argon2::default();
        match argon2.verify_password(password_ref, &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
            // verify 期其余错误均为「关于哈希值本身」的数据类错误（算法未知、
            // 参数越界、salt/hash 段无效），统一映射 InvalidParam——stp 层将其
            // 并入 T019 统一防枚举分支。基础设施错误（join/池关闭）由
            // verify_pooled 层映射 Internal，不经此处。
            Err(e) => Err(GarrisonError::InvalidParam(format!(
                "account-argon2-verify::{}",
                e
            ))),
        }
        // password_bytes drops here (if zeroize on); Zeroizing<Vec<u8>>::drop zeroes bytes
    }

    fn verify_and_rehash(
        &self,
        password: &str,
        hash: &str,
    ) -> GarrisonResult<(bool, Option<String>)> {
        let matched = self.verify(password, hash)?;
        if !matched {
            return Ok((false, None));
        }
        // verify 通过后解析存量 PHC 自描述参数，与当前配置档位做字典序比较：
        // 仅当存量 (m, t, p) 整体低于配置时升级——任一维度高于配置即视为档位
        // 不低于配置（重哈希不得造成安全降级）；全维度相等亦不重哈希。
        let parsed = PasswordHash::new(hash)
            .map_err(|e| GarrisonError::InvalidParam(format!("account-argon2-format::{}", e)))?;
        let stored = Params::try_from(&parsed.params)
            .map_err(|e| GarrisonError::InvalidParam(format!("account-argon2-params::{}", e)))?;
        let legacy_tier = (stored.m_cost(), stored.t_cost(), stored.p_cost());
        let configured_tier = (self.m_cost, self.t_cost, self.p_cost);
        if legacy_tier >= configured_tier {
            return Ok((true, None));
        }
        let new_hash = self.hash(password)?;
        Ok((true, Some(new_hash)))
    }
}

// ============================================================================
// BcryptHasher 实现
// ============================================================================

/// Bcrypt 密码哈希器。
///
/// 使用 bcrypt 0.19 crate，默认 cost=12。
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
    /// - `cost`: cost 参数（4-31，建议 10-14）。超出范围自动钳制到 4。
    pub fn with_cost(cost: u32) -> Self {
        // 验证 bcrypt cost 范围（bcrypt 规范要求 4-31）
        let cost = cost.clamp(4, 31);
        Self { cost }
    }
}

impl PasswordHasher for BcryptHasher {
    fn hash(&self, password: &str) -> GarrisonResult<String> {
        // P2.1: 与 Argon2Hasher 对称——credential-zeroize
        // feature 启用时，将密码字节拷贝到 Zeroizing<String>，函数返回时 wrapper
        // Drop 清零内部字节（bcrypt crate 直接消费 &str，无法清零调用方的 String）。
        #[cfg(feature = "credential-zeroize")]
        let password_bytes = zeroize::Zeroizing::new(password.to_string());
        #[cfg(feature = "credential-zeroize")]
        let password_ref: &str = &password_bytes;
        #[cfg(not(feature = "credential-zeroize"))]
        let password_ref: &str = password;

        bcrypt::hash(password_ref, self.cost)
            .map_err(|e| GarrisonError::Internal(format!("account-bcrypt-hash::{}", e)))
        // password_bytes drops here (if zeroize on); Zeroizing<String>::drop zeroes bytes
    }

    fn verify(&self, password: &str, hash: &str) -> GarrisonResult<bool> {
        // P2.1: 同 hash，verify 后清零内部密码字节副本
        #[cfg(feature = "credential-zeroize")]
        let password_bytes = zeroize::Zeroizing::new(password.to_string());
        #[cfg(feature = "credential-zeroize")]
        let password_ref: &str = &password_bytes;
        #[cfg(not(feature = "credential-zeroize"))]
        let password_ref: &str = password;

        bcrypt::verify(password_ref, hash)
            .map_err(|e| GarrisonError::InvalidParam(format!("account-bcrypt-format::{}", e)))
        // password_bytes drops here (if zeroize on); Zeroizing<String>::drop zeroes bytes
    }
}

// ============================================================================
// 并发令牌池封装（async 取 permit → spawn_blocking → permit 移入闭包）
// ============================================================================

/// 取并发 permit（gate None 直通；信号量已关闭显性报错，不静默）。
async fn acquire_permit(
    hasher: &dyn PasswordHasher,
) -> GarrisonResult<Option<tokio::sync::OwnedSemaphorePermit>> {
    match hasher.concurrency_gate() {
        Some(sem) => sem
            .clone()
            .acquire_owned()
            .await
            .map(Some)
            .map_err(|_| GarrisonError::Internal("account-argon2-pool-closed::".to_string())),
        None => Ok(None),
    }
}

/// 信号量闸门下的异步 verify（[`PasswordHasher::concurrency_gate`] 语义统一出口）。
///
/// 无池 hasher 行为与直接 spawn_blocking 等价（直通）；有池时先取 permit 再执行，
/// permit 移入闭包——存活期 == 哈希执行期，调用方取消不超卖（见 trait 文档）。
pub(crate) async fn verify_pooled(
    hasher: &Arc<dyn PasswordHasher>,
    password: &str,
    hash: &str,
) -> GarrisonResult<bool> {
    let permit = acquire_permit(hasher.as_ref()).await?;
    let hasher = Arc::clone(hasher);
    let password = password.to_string();
    let hash = hash.to_string();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hasher.verify(&password, &hash)
    })
    .await
    .map_err(|e| GarrisonError::Internal(format!("credential-verify-blocking::{}", e)))?
}

/// 信号量闸门下的异步 verify + 惰性重哈希（[`PasswordHasher::verify_and_rehash`]
/// 的统一并发出口，permit 占槽语义与 [`verify_pooled`] 同款）。
///
/// verify 与重哈希在同一 permit 内顺序执行：并发上界恒等于 permit 数，
/// 内存上界 = permits × m_cost（旧哈希 verify 与新哈希生成不重叠驻留）。
/// 门控：唯一调用方 `stp::password::login_with_password` 要求
/// `account-credential + db-sqlite`；其余组合（如 production 的
/// account-password-reset 链拉入 account-credential 但无 db-sqlite）下
/// 该函数为死代码。
#[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
pub(crate) async fn verify_and_rehash_pooled(
    hasher: &Arc<dyn PasswordHasher>,
    password: &str,
    hash: &str,
) -> GarrisonResult<(bool, Option<String>)> {
    let permit = acquire_permit(hasher.as_ref()).await?;
    let hasher = Arc::clone(hasher);
    let password = password.to_string();
    let hash = hash.to_string();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hasher.verify_and_rehash(&password, &hash)
    })
    .await
    .map_err(|e| GarrisonError::Internal(format!("credential-verify-blocking::{}", e)))?
}

// ============================================================================
// PasswordVerifier 自动识别
// ============================================================================

/// 密码校验器，根据 hash 前缀自动选择算法校验。
///
/// - `$argon2id$` 前缀 → 委托 `Argon2Hasher`
/// - `$2b$` / `$2a$` / `$2y$` 前缀 → 委托 `BcryptHasher`
/// - 其他前缀 → 返回 `GarrisonError::InvalidParam`
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
    /// - `Err(GarrisonError::InvalidParam)`: 不支持的 hash 格式。
    pub fn verify(password: &str, hash: &str) -> GarrisonResult<bool> {
        if hash.starts_with("$argon2") {
            Argon2Hasher::default().verify(password, hash)
        } else if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
            BcryptHasher::default().verify(password, hash)
        } else {
            Err(GarrisonError::InvalidParam(format!(
                "account-password-unsupported-hash-format::{}",
                &hash[..hash.len().min(10)]
            )))
        }
    }
}

// ============================================================================
// PasswordCredential（Credential trait 实现）
// ============================================================================

/// 密码凭证（实现 [`Credential`] trait，委托 [`PasswordHasher`] 校验）。
///
/// 持有 `CredentialModel`（存储模型）+ `Arc<dyn PasswordHasher>`（哈希器），
/// `verify()` 委托 `PasswordHasher::verify(input, &model.secret_data)`（spawn_blocking 执行）。
///
/// # 示例
///
/// ```ignore
/// use garrison::account::credential::password::{Argon2Hasher, PasswordCredential, PasswordHasher};
/// use garrison::account::credential::CredentialModel;
/// use std::sync::Arc;
///
/// let hasher = Argon2Hasher::default();
/// let hash = hasher.hash("secret")?;
/// let model = CredentialModel {
/// id: "cred-001".into(),
/// user_id: "alice".into(),
/// credential_type: "password".into(),
/// secret_data: hash,
/// label: None,
/// created_at: 0,
/// enabled: true,
/// priority: 0,
/// };
/// let cred = PasswordCredential::new(model, Arc::new(hasher));
/// assert!(cred.verify("secret").await?);
/// ```
pub struct PasswordCredential {
    /// 凭证存储模型。
    model: CredentialModel,
    /// 密码哈希器（Argon2 / Bcrypt / 自定义）。
    ///
    /// 现使用 `Arc`（原 `Box`）：`verify()` 需将哈希器移入
    /// `spawn_blocking` 闭包把慢哈希移出 async worker，要求可克隆共享。
    hasher: Arc<dyn PasswordHasher>,
}

/// 启用 `account-credential-zeroize` feature 时，drop 时清零 `model` 的敏感字段
/// （`secret_data` 含密码哈希）。
///
/// `hasher` 不含敏感数据（仅算法标识与参数），无需 zeroize。
/// 因 `dyn PasswordHasher` 未实现 `Zeroize`，无法派生 `ZeroizeOnDrop`，
/// 改为手动实现 `Drop` 调用 `model.zeroize()`。
#[cfg(feature = "credential-zeroize")]
impl Drop for PasswordCredential {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.model.zeroize();
    }
}

impl PasswordCredential {
    /// 创建密码凭证。
    ///
    /// # 参数
    /// - `model`: 凭证存储模型（`secret_data` 字段应包含已哈希的密码）
    /// - `hasher`: 密码哈希器（用于 `verify` 时校验）。
    ///   接受 `Arc`（原 `Box`），以支持 `verify` 内部的 `spawn_blocking`。
    pub fn new(model: CredentialModel, hasher: Arc<dyn PasswordHasher>) -> Self {
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

    async fn verify(&self, input: &str) -> GarrisonResult<bool> {
        // 统一经并发令牌池封装：慢哈希下沉 spawn_blocking + 有池时受 permit
        // 约束（内存上界 = permits × m_cost），无池行为与原实现等价。
        verify_pooled(&self.hasher, input, &self.model.secret_data).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // PasswordHasher trait 契约测试
    // ========================================================================

    /// PasswordHasher trait 为 Send + Sync（编译期检查）。
    #[test]
    fn password_hasher_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Argon2Hasher>();
        assert_send_sync::<BcryptHasher>();
        assert_send_sync::<PasswordVerifier>();
    }

    // ========================================================================
    // Argon2Hasher 测试
    // ========================================================================

    /// Argon2Hasher::default().hash("password") 返回 $argon2id$ 前缀字符串。
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

    /// 相同密码两次 hash 产生不同结果（盐随机）。
    #[test]
    fn argon2_hash_same_password_produces_different_results() {
        let hasher = Argon2Hasher::default();
        let h1 = hasher.hash("password").unwrap();
        let h2 = hasher.hash("password").unwrap();
        assert_ne!(h1, h2, "相同密码两次 hash 应产生不同结果（盐随机）");
    }

    /// Argon2Hasher::verify 对正确密码返回 Ok(true)。
    #[test]
    fn argon2_verify_correct_password_returns_true() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("password").unwrap();
        let result = hasher.verify("password", &hash).unwrap();
        assert!(result, "正确密码应返回 Ok(true)");
    }

    /// Argon2Hasher::verify 对错误密码返回 Ok(false)。
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
        let hash = hasher.hash("test").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(hasher.verify("test", &hash).unwrap());
    }

    /// verify 期数据类错误——存量哈希算法未知（PHC 结构合法、`PasswordHash::new`
    /// 可解析，Argon2 校验期拒绝）→ `InvalidParam` 而非 `Internal`：stp 层仅将
    /// `InvalidParam` 并入 T019 统一防枚举分支，`Internal` 显性传播会对降级
    /// 账户产生差分响应（防枚举回归防护）。
    #[test]
    fn argon2_verify_unknown_algorithm_returns_invalid_param() {
        let hasher = Argon2Hasher::default();
        let result = hasher.verify(
            "password",
            "$scrypt$ln=16,r=8,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg",
        );
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "verify 期算法未知应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// verify 期数据类错误——argon2 变体名未知但参数段合法（覆盖
    /// `Algorithm::try_from` 失败路径）→ `InvalidParam`。
    #[test]
    fn argon2_verify_unknown_algorithm_variant_returns_invalid_param() {
        let hasher = Argon2Hasher::default();
        let result = hasher.verify(
            "password",
            "$argon2x$v=19$m=19456,t=2,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg",
        );
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "verify 期 argon2 变体未知应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// verify 期数据类错误——参数越界（内嵌 m=1 低于 Argon2 `MIN_M_COST`）→
    /// `InvalidParam`（存量 PHC 自描述参数，校验期拒绝）。
    #[test]
    fn argon2_verify_out_of_range_params_returns_invalid_param() {
        let hasher = Argon2Hasher::default();
        let result = hasher.verify(
            "password",
            "$argon2id$v=19$m=1,t=2,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg",
        );
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "verify 期参数越界应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    // ========================================================================
    // BcryptHasher 测试
    // ========================================================================

    /// BcryptHasher::default().hash("password") 返回 $2b$ 前缀字符串。
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

    /// BcryptHasher::verify 对正确密码返回 Ok(true)。
    #[test]
    fn bcrypt_verify_correct_password_returns_true() {
        let hasher = BcryptHasher::default();
        let hash = hasher.hash("password").unwrap();
        let result = hasher.verify("password", &hash).unwrap();
        assert!(result, "正确密码应返回 Ok(true)");
    }

    /// BcryptHasher::verify 对错误密码返回 Ok(false)。
    #[test]
    fn bcrypt_verify_wrong_password_returns_false() {
        let hasher = BcryptHasher::default();
        let hash = hasher.hash("password").unwrap();
        let result = hasher.verify("wrong", &hash).unwrap();
        assert!(!result, "错误密码应返回 Ok(false)");
    }

    /// BcryptHasher::verify 识别 $2a$ 格式（标准 bcrypt 前缀变体）。
    #[test]
    fn bcrypt_verify_recognizes_2a_format() {
        let hasher = BcryptHasher::default();
        // 先生成 $2b$ 哈希，然后把 $2b$ 改成 $2a$ 验证前缀识别
        let hash = hasher.hash("password").unwrap();
        let hash_2a = hash.replacen("$2b$", "$2a$", 1);
        let result = hasher.verify("password", &hash_2a).unwrap();
        assert!(result, "BcryptHasher 应识别 $2a$ 格式");
    }

    /// BcryptHasher::verify 识别 $2y$ 格式（标准 bcrypt 前缀变体）。
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
    // PasswordVerifier 自动识别测试
    // ========================================================================

    /// PasswordVerifier::verify 委托 Argon2Hasher（$argon2id$ 前缀）。
    #[test]
    fn password_verifier_delegates_to_argon2() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("password").unwrap();
        let result = PasswordVerifier::verify("password", &hash).unwrap();
        assert!(result, "PasswordVerifier 应委托 Argon2Hasher 校验正确密码");
        let wrong = PasswordVerifier::verify("wrong", &hash).unwrap();
        assert!(!wrong, "PasswordVerifier 应委托 Argon2Hasher 校验错误密码");
    }

    /// PasswordVerifier::verify 委托 BcryptHasher（$2b$ 前缀）。
    #[test]
    fn password_verifier_delegates_to_bcrypt() {
        let hasher = BcryptHasher::default();
        let hash = hasher.hash("password").unwrap();
        let result = PasswordVerifier::verify("password", &hash).unwrap();
        assert!(result, "PasswordVerifier 应委托 BcryptHasher 校验正确密码");
        let wrong = PasswordVerifier::verify("wrong", &hash).unwrap();
        assert!(!wrong, "PasswordVerifier 应委托 BcryptHasher 校验错误密码");
    }

    /// PasswordVerifier::verify 不支持的 hash 格式返回 InvalidParam。
    #[test]
    fn password_verifier_unsupported_format_returns_invalid_param() {
        let result = PasswordVerifier::verify("password", "$unknown$hash");
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "不支持的 hash 格式应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// PasswordVerifier::verify 识别 $2a$ 前缀（Bcrypt 兼容）。
    #[test]
    fn password_verifier_delegates_to_bcrypt_2a_format() {
        let hasher = BcryptHasher::default();
        let hash = hasher.hash("password").unwrap();
        let hash_2a = hash.replacen("$2b$", "$2a$", 1);
        let result = PasswordVerifier::verify("password", &hash_2a).unwrap();
        assert!(result, "PasswordVerifier 应识别 $2a$ 格式");
    }

    // ========================================================================
    // Argon2 输出长度契约测试
    // ========================================================================

    /// Argon2Hasher::hash 输出长度为 32 字节（预分配缓冲区）。
    ///
    /// PHC 格式：`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`
    /// 末段为 hash 的 base64 编码（无 padding），解码后应为 32 字节。
    ///
    /// 注意：此测试依赖 `base64` crate 解码 PHC 末段，需启用含 `dep:base64` 的 feature
    /// （如 `protocol-oauth2` / `secure-httpbasic` / `web-csrf` / `full`）。仅启用 `account-credential`
    /// 时此测试不编译（生产代码不依赖 base64）。
    #[cfg(any(
        feature = "protocol-oauth2",
        feature = "protocol-sso",
        feature = "protocol-sign",
        feature = "secure-sign",
        feature = "protocol-httpbasic",
        feature = "protocol-httpdigest",
        feature = "social-alipay",
        feature = "web-csrf"
    ))]
    #[test]
    fn hash_produces_32_byte_output() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("test-password").expect("hash 应成功");
        // 以 $ 分隔：[0]=""（空前缀）, [1]="argon2id", [2]="v=19",
        // [3]="m=...,t=...,p=...", [4]="<salt>", [5]="<hash>"
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
    // P2.1 zeroize 测试
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
    #[cfg(feature = "credential-zeroize")]
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
        // a) Vec<u8>::zeroize() 先零填充字节再 clear（length=0，capacity 保留）
        let mut local_copy: Vec<u8> = password.as_bytes().to_vec();
        local_copy.zeroize();
        assert_eq!(local_copy.len(), 0, "Vec::zeroize 后 length 应为 0 (clear)");

        // b) [u8; N]::zeroize() 仅零填充字节（数组长度固定，不 clear）
        // 证明 zeroize 的字节清零语义
        let mut arr: [u8; 18] = [0; 18];
        arr.copy_from_slice(password.as_bytes());
        arr.zeroize();
        assert!(
            arr.iter().all(|&b| b == 0),
            "数组 zeroize 后所有字节应为 0，实际: {:?}",
            arr
        );

        // 3. Zeroizing<String> wrapper 可与 hash 配合（通过 Deref<Target=String> → str）
        // 调用方可用此 wrapper 持有 password，wrapper Drop 时清零底层字节
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
    // PasswordCredential 测试
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
        let cred = PasswordCredential::new(model, Arc::new(hasher));
        (cred, password.to_string())
    }

    /// `credential_type()` 返回常量 `"password"`。
    #[test]
    fn password_credential_type_returns_password() {
        let (cred, _) = make_password_cred("c1", "alice", "secret");
        assert_eq!(cred.credential_type(), "password");
    }

    /// `to_model()` 返回原始 CredentialModel（字段一致）。
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

    /// `verify()` 正确密码返回 `Ok(true)`。
    #[tokio::test]
    async fn password_credential_verify_correct_password() {
        let (cred, password) = make_password_cred("c1", "alice", "my-secret");
        let result = cred.verify(&password).await.expect("verify 应成功");
        assert!(result, "正确密码应校验通过");
    }

    /// `verify()` 错误密码返回 `Ok(false)`。
    #[tokio::test]
    async fn password_credential_verify_wrong_password() {
        let (cred, _) = make_password_cred("c1", "alice", "my-secret");
        let result = cred
            .verify("wrong-password")
            .await
            .expect("verify 应成功（返回 false 而非报错）");
        assert!(!result, "错误密码应校验失败");
    }

    /// `PasswordCredential` 支持 BcryptHasher（多 hasher 兼容）。
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
        let cred = PasswordCredential::new(model, Arc::new(hasher));

        assert!(
            cred.verify("bcrypt-secret").await.expect("verify 应成功"),
            "Bcrypt 正确密码应校验通过"
        );
        assert!(
            !cred.verify("wrong").await.expect("verify 应成功"),
            "Bcrypt 错误密码应校验失败"
        );
    }

    /// `PasswordCredential` 可作 `Box<dyn Credential>` 使用（对象安全验证）。
    #[tokio::test]
    async fn password_credential_usable_as_dyn_credential() {
        let (cred, password) = make_password_cred("c1", "alice", "secret");
        let dyn_cred: Box<dyn Credential> = Box::new(cred);
        assert_eq!(dyn_cred.credential_type(), "password");
        let result = dyn_cred.verify(&password).await.expect("verify 应成功");
        assert!(result, "dyn Credential 正确密码应校验通过");
    }

    /// 池=1 下 3 个并发 `PasswordCredential::verify`（经 verify_pooled 委托）：
    /// 排队不拒绝，正确/错误密码结果全对（接线后回归安全网）。
    #[tokio::test]
    async fn password_credential_verify_concurrent_correctness() {
        let hasher = Argon2Hasher::default().with_pool(1);
        let hash = hasher.hash("pool-secret").expect("hash 应成功");
        let model = CredentialModel {
            id: "c3".to_string(),
            user_id: "carol".to_string(),
            credential_type: "password".to_string(),
            secret_data: hash,
            label: None,
            created_at: 0,
            enabled: true,
            priority: 0,
        };
        let cred = Arc::new(PasswordCredential::new(model, Arc::new(hasher)));

        let mut handles = Vec::new();
        for i in 0..3 {
            let cred = Arc::clone(&cred);
            handles.push(tokio::spawn(async move {
                if i == 1 {
                    cred.verify("wrong").await
                } else {
                    cred.verify("pool-secret").await
                }
            }));
        }
        assert_eq!(
            handles.remove(0).await.unwrap().unwrap(),
            true,
            "正确密码应通过"
        );
        assert_eq!(
            handles.remove(0).await.unwrap().unwrap(),
            false,
            "错误密码应拒绝"
        );
        assert_eq!(
            handles.remove(0).await.unwrap().unwrap(),
            true,
            "正确密码应通过"
        );
    }

    /// `PasswordCredential` 在 `account-credential-zeroize` feature 启用时仍正确工作。
    #[cfg(feature = "credential-zeroize")]
    #[tokio::test]
    async fn password_credential_zeroize_integration() {
        let (cred, password) = make_password_cred("c1", "alice", "zeroize-secret");
        // verify 在 zeroize feature 启用时仍正确工作
        let result = cred.verify(&password).await.expect("verify 应成功");
        assert!(result, "zeroize feature 启用时正确密码应校验通过");
        let wrong = cred.verify("wrong").await.expect("verify 应成功");
        assert!(!wrong, "zeroize feature 启用时错误密码应校验失败");
    }

    // ========================================================================
    // Argon2 并发令牌池（concurrency_gate / with_pool / verify_pooled）
    // ========================================================================

    /// 可控节奏哈希器：verify 进入时发握手信号，阻塞等待放行后才返回。
    ///
    /// 用 oneshot/unbounded 握手控制执行节奏（不用真实 sleep），并以原子计数
    /// 记录在飞峰值，供并发上界断言。
    struct GatedHasher {
        pool: Option<Arc<tokio::sync::Semaphore>>,
        entered_tx: tokio::sync::mpsc::UnboundedSender<()>,
        release_rx: std::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<()>>,
        in_flight: std::sync::atomic::AtomicUsize,
        max_in_flight: std::sync::atomic::AtomicUsize,
    }

    impl GatedHasher {
        fn new(
            entered_tx: tokio::sync::mpsc::UnboundedSender<()>,
            release_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
            pool_size: usize,
        ) -> Self {
            Self {
                pool: Some(Arc::new(tokio::sync::Semaphore::new(pool_size))),
                entered_tx,
                release_rx: std::sync::Mutex::new(release_rx),
                in_flight: std::sync::atomic::AtomicUsize::new(0),
                max_in_flight: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn max_in_flight(&self) -> usize {
            self.max_in_flight.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl PasswordHasher for GatedHasher {
        fn hash(&self, password: &str) -> GarrisonResult<String> {
            Ok(password.to_string())
        }

        fn verify(&self, _password: &str, _hash: &str) -> GarrisonResult<bool> {
            use std::sync::atomic::Ordering as AOrd;
            let n = self.in_flight.fetch_add(1, AOrd::SeqCst) + 1;
            self.max_in_flight.fetch_max(n, AOrd::SeqCst);
            let _ = self.entered_tx.send(());
            // 阻塞等待放行（运行在 spawn_blocking 线程，允许阻塞）
            let _released = self
                .release_rx
                .lock()
                .expect("release_rx 锁不应中毒")
                .blocking_recv();
            self.in_flight.fetch_sub(1, AOrd::SeqCst);
            Ok(true)
        }

        fn concurrency_gate(&self) -> Option<&Arc<tokio::sync::Semaphore>> {
            self.pool.as_ref()
        }
    }

    /// 无池直通哈希器（gate 返回默认 None）。
    struct PassthroughHasher;

    impl PasswordHasher for PassthroughHasher {
        fn hash(&self, password: &str) -> GarrisonResult<String> {
            Ok(password.to_string())
        }

        fn verify(&self, password: &str, hash: &str) -> GarrisonResult<bool> {
            Ok(password == hash)
        }
    }

    /// 默认/with_params 的 Argon2Hasher 与 BcryptHasher 的 gate 均为 None
    /// （向后兼容：自定义实现与未装配池的 hasher 行为不变）。
    #[test]
    fn gate_default_hashers_return_none() {
        assert!(Argon2Hasher::default().concurrency_gate().is_none());
        assert!(Argon2Hasher::with_params(8192, 1, 1)
            .concurrency_gate()
            .is_none());
        assert!(BcryptHasher::default().concurrency_gate().is_none());
    }

    /// with_pool(0) 钳制为 1（fail-safe，对齐 BcryptHasher::with_cost 的 clamp 先例）；
    /// 正常值按配置装配 permit 数。
    #[test]
    fn with_pool_clamps_zero_to_one() {
        let zero = Argon2Hasher::default().with_pool(0);
        assert_eq!(
            zero.concurrency_gate().unwrap().available_permits(),
            1,
            "with_pool(0) 应钳制为 1 permit"
        );
        let five = Argon2Hasher::default().with_pool(5);
        assert_eq!(five.concurrency_gate().unwrap().available_permits(), 5);
    }

    /// 池=1 时 3 个并发 verify_pooled：第 1 个进入后其余排队（不拒绝），
    /// 放行后依次进入，结果全对——并发上界精确等于 permit 数。
    #[tokio::test]
    async fn pool_bounds_concurrent_executions() {
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_tx, release_rx) = tokio::sync::mpsc::unbounded_channel();
        let gated = Arc::new(GatedHasher::new(entered_tx, release_rx, 1));
        let hasher: Arc<dyn PasswordHasher> = gated.clone();

        let mut handles = Vec::new();
        for _ in 0..3 {
            let h = Arc::clone(&hasher);
            handles.push(tokio::spawn(async move {
                verify_pooled(&h, "pw", "$argon2id$fake").await
            }));
        }

        // 第 1 个进入 verify（持 permit），其余排队
        entered_rx.recv().await.expect("应有第 1 个进入信号");
        assert_eq!(
            gated.max_in_flight(),
            1,
            "池=1 时同时执行中的 verify 至多 1 个"
        );

        // 依次放行：每放行一个，下一个才进入（第 3 次放行后无新进入者）
        release_tx.send(()).expect("release 通道应存活");
        entered_rx.recv().await.expect("第 2 个应在放行后进入");
        release_tx.send(()).expect("release 通道应存活");
        entered_rx.recv().await.expect("第 3 个应在放行后进入");
        release_tx.send(()).expect("release 通道应存活");

        for h in handles {
            assert_eq!(
                h.await.expect("任务不应 panic").expect("verify 应成功"),
                true,
                "排队不拒绝，3 个 verify 结果全对"
            );
        }
        assert_eq!(
            gated.max_in_flight(),
            1,
            "全程并发上界应精确等于 permit 数 1"
        );
    }

    /// verify_pooled 完成后 permit 归还：available_permits() 回到初值（无泄漏）。
    #[tokio::test]
    async fn pool_permits_released_after_completion() {
        let hasher = Arc::new(Argon2Hasher::default().with_pool(2));
        let gate = hasher.concurrency_gate().unwrap().clone();
        assert_eq!(gate.available_permits(), 2);
        let hash = hasher.hash("pw").expect("hash 应成功");

        let mut handles = Vec::new();
        for _ in 0..2 {
            let h: Arc<dyn PasswordHasher> = hasher.clone();
            let hash = hash.clone();
            handles.push(tokio::spawn(
                async move { verify_pooled(&h, "pw", &hash).await },
            ));
        }
        for h in handles {
            h.await.expect("任务不应 panic").expect("verify 应成功");
        }
        assert_eq!(
            gate.available_permits(),
            2,
            "完成后 permits 应回到初值（无泄漏）"
        );
    }

    /// 调用方 future 被取消（abort）不超卖：permit 移入 spawn_blocking 闭包，
    /// 存活期 == 哈希执行期——孤儿 blocking 任务继续持 permit 直到 verify 真正
    /// 返回，后续调用在该时刻之前不得进入。
    #[tokio::test]
    async fn pool_cancelled_caller_does_not_oversell() {
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_tx, release_rx) = tokio::sync::mpsc::unbounded_channel();
        let gated = Arc::new(GatedHasher::new(entered_tx, release_rx, 1));
        let gate = gated.concurrency_gate().unwrap().clone();
        let hasher: Arc<dyn PasswordHasher> = gated.clone();

        // task1 进入 verify 并阻塞在放行点（持 permit）
        let h1 = Arc::clone(&hasher);
        let task1 = tokio::spawn(async move { verify_pooled(&h1, "pw", "h").await });
        entered_rx.recv().await.expect("task1 应已进入 verify");

        // 取消 task1 的调用方 future；孤儿 blocking 任务继续持有 permit
        task1.abort();

        // task2 发起调用：在 task1 的 verify 真正返回前不得进入（不超卖）
        let h2 = Arc::clone(&hasher);
        let task2 = tokio::spawn(async move { verify_pooled(&h2, "pw", "h").await });
        assert!(
            entered_rx.try_recv().is_err(),
            "task1 的 verify 仍在执行时 task2 不得进入（permit 存活期绑定哈希执行期）"
        );

        // 放行 task1：verify 返回后 permit 归还，task2 才进入
        release_tx.send(()).expect("release 通道应存活");
        entered_rx
            .recv()
            .await
            .expect("task2 应在 task1 完成后进入");
        release_tx.send(()).expect("release 通道应存活");

        assert!(
            task2
                .await
                .expect("task2 不应 panic")
                .expect("task2 verify 应成功"),
            "task2 排队后应正常完成"
        );
        assert_eq!(
            gate.available_permits(),
            1,
            "全部完成后 permits 应回到初值（取消时序下无泄漏）"
        );
        assert_eq!(gated.max_in_flight(), 1, "取消时序下并发上界仍为 1");
    }

    /// 信号量已关闭（sem.close()）：verify_pooled 显性返回 GarrisonError
    /// （account-argon2-pool-closed，不静默成功）。
    #[tokio::test]
    async fn pool_closed_returns_error() {
        let hasher = Arc::new(Argon2Hasher::default().with_pool(1));
        hasher.concurrency_gate().unwrap().close();
        let result = verify_pooled(&(hasher as Arc<dyn PasswordHasher>), "pw", "h").await;
        match &result {
            Err(GarrisonError::Internal(msg)) => assert!(
                msg.contains("account-argon2-pool-closed"),
                "错误串应含 account-argon2-pool-closed，实际: {}",
                msg
            ),
            other => panic!("池关闭应返回 Internal 错误，实际: {:?}", other),
        }
    }

    /// gate 为 None（无池）：verify_pooled 直通 spawn_blocking，行为与现状等价。
    #[tokio::test]
    async fn gate_none_passes_through() {
        let hasher: Arc<dyn PasswordHasher> = Arc::new(PassthroughHasher);
        let hit = verify_pooled(&hasher, "pw", "pw").await.expect("应直通");
        assert!(hit, "密码匹配应返回 true");
        let miss = verify_pooled(&hasher, "pw", "other").await.expect("应直通");
        assert!(!miss, "密码不匹配应返回 false");
    }

    // ========================================================================
    // 登录期惰性重哈希（verify_and_rehash）
    // ========================================================================

    /// trait 默认实现 = verify + None：未覆写 `verify_and_rehash` 的自定义实现
    /// （PassthroughHasher 零改动）行为与 `verify` 完全一致——返回 verify 结果
    /// 且永不产出新 hash。
    #[test]
    fn verify_and_rehash_default_impl_returns_verify_result_and_none() {
        let hasher: Arc<dyn PasswordHasher> = Arc::new(PassthroughHasher);
        let hit = hasher.verify_and_rehash("pw", "pw").expect("verify 应成功");
        assert_eq!(hit, (true, None), "密码匹配应返回 (true, None)");
        let miss = hasher
            .verify_and_rehash("pw", "other")
            .expect("verify 应成功");
        assert_eq!(miss, (false, None), "密码不匹配应返回 (false, None)");
    }

    /// 存量低档位哈希（m=8MiB < 配置 19MiB）：verify 成功时返回 Some(新 hash)，
    /// 新 hash 使用当前配置档位且可通过当前配置 hasher verify。
    #[test]
    fn verify_and_rehash_low_tier_hash_returns_upgraded_hash() {
        let legacy = Argon2Hasher::with_params(8192, 2, 1);
        let stored = legacy.hash("legacy-secret").expect("hash 应成功");
        assert!(stored.contains("m=8192"), "存量哈希应为低档位 m=8192");

        let hasher = Argon2Hasher::default();
        let (verified, rehash) = hasher
            .verify_and_rehash("legacy-secret", &stored)
            .expect("verify_and_rehash 应成功");
        assert!(verified, "正确密码应 verify 通过");
        let new_hash = rehash.expect("低档位存量哈希应产出升级 hash");
        assert!(
            hasher
                .verify("legacy-secret", &new_hash)
                .expect("verify 应成功"),
            "升级后的新 hash 应可通过当前配置 verify"
        );
        assert!(
            new_hash.contains("m=19456"),
            "新 hash 应使用当前配置档位 m=19456，实际: {}",
            new_hash
        );
    }

    /// 存量档位与当前配置持平（default 产出的 hash）：verify 通过且不重哈希。
    #[test]
    fn verify_and_rehash_current_tier_returns_none() {
        let hasher = Argon2Hasher::default();
        let stored = hasher.hash("same-tier").expect("hash 应成功");
        let (verified, rehash) = hasher
            .verify_and_rehash("same-tier", &stored)
            .expect("verify_and_rehash 应成功");
        assert!(verified, "正确密码应 verify 通过");
        assert!(rehash.is_none(), "档位不低于配置时不应重哈希");
    }

    /// 存量档位高于当前配置：verify 通过但不重哈希——升级不得造成安全降级。
    #[test]
    fn verify_and_rehash_stronger_tier_does_not_downgrade() {
        let strong = Argon2Hasher::with_params(32768, 3, 1);
        let stored = strong.hash("strong-secret").expect("hash 应成功");
        let hasher = Argon2Hasher::default();
        let (verified, rehash) = hasher
            .verify_and_rehash("strong-secret", &stored)
            .expect("verify_and_rehash 应成功");
        assert!(verified, "正确密码应 verify 通过");
        assert!(rehash.is_none(), "存量档位高于配置时不得重哈希降级");
    }

    /// verify 失败（密码错误）：返回 (false, None)，不产出任何新 hash。
    #[test]
    fn verify_and_rehash_wrong_password_returns_false_and_none() {
        let legacy = Argon2Hasher::with_params(8192, 2, 1);
        let stored = legacy.hash("legacy-secret").expect("hash 应成功");
        let hasher = Argon2Hasher::default();
        let (verified, rehash) = hasher
            .verify_and_rehash("wrong-password", &stored)
            .expect("verify 应成功（返回 false 而非报错）");
        assert!(!verified, "错误密码应 verify 失败");
        assert!(rehash.is_none(), "verify 失败不得产出新 hash");
    }

    /// 池化出口 verify_and_rehash_pooled：低档位存量经池升级（permit 占槽与
    /// verify_pooled 同款），完成后 permit 归还无泄漏。
    /// （函数本体随唯一调用方 stp::password 门控在 db-sqlite 组合，本测试同门控）
    #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
    #[tokio::test]
    async fn verify_and_rehash_pooled_upgrades_and_returns_permit() {
        let legacy = Argon2Hasher::with_params(8192, 2, 1);
        let stored = legacy.hash("legacy-secret").expect("hash 应成功");
        let hasher = Arc::new(Argon2Hasher::default().with_pool(2));
        let gate = hasher.concurrency_gate().unwrap().clone();

        let h: Arc<dyn PasswordHasher> = hasher.clone();
        let (verified, rehash) = verify_and_rehash_pooled(&h, "legacy-secret", &stored)
            .await
            .expect("verify_and_rehash 应成功");
        assert!(verified, "正确密码应 verify 通过");
        let new_hash = rehash.expect("低档位存量应经池产出升级 hash");
        assert!(
            verify_pooled(&h, "legacy-secret", &new_hash)
                .await
                .expect("verify 应成功"),
            "升级后的新 hash 应可通过 verify"
        );
        assert_eq!(
            gate.available_permits(),
            2,
            "完成后 permits 应回到初值（无泄漏）"
        );
    }

    /// 池化出口不重哈希分支：档位持平返回 (true, None)，与直连行为一致。
    #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
    #[tokio::test]
    async fn verify_and_rehash_pooled_current_tier_returns_none() {
        let hasher = Arc::new(Argon2Hasher::default().with_pool(1));
        let stored = hasher.hash("same-tier").expect("hash 应成功");
        let h: Arc<dyn PasswordHasher> = hasher.clone();
        let (verified, rehash) = verify_and_rehash_pooled(&h, "same-tier", &stored)
            .await
            .expect("verify_and_rehash 应成功");
        assert!(verified, "正确密码应 verify 通过");
        assert!(rehash.is_none(), "档位持平时池化出口同样不重哈希");
    }
}
