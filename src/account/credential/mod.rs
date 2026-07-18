//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 凭证模型 SPI 子模块（吸收 keycloak CredentialModel SPI）。
//! 提供统一凭证抽象，支持 password / TOTP / WebAuthn（v0.7+）等多种凭证类型。
//! 详见 spec `credential-model`。
//!
//! # 核心类型
//!
//! - `Credential` trait：统一凭证校验接口（对象安全，可作 `dyn Credential`）
//! - `CredentialModel`：凭证存储模型（DAO 持久化结构，8 字段 schema）
//! - `CredentialRepository` trait：凭证存储抽象（CRUD 5 方法）
//!
//! # 设计决策
//!
//! - D1: `Credential::verify(&self, input: &str)` 接收 `&str` 而非泛型（对象安全）
//! - D5: `PasswordHasher` 从 `secure/password/` 破坏性迁移到本模块的 `password` 子模块

/// 密码哈希子模块（v0.6.0 从 secure/password/ 迁移）。
///
/// 提供 `PasswordHasher` trait + `Argon2Hasher` / `BcryptHasher` + `PasswordVerifier`。
pub mod password;

// 模块重导出：通过 mod 路径访问子模块类型（避免外部代码引用具体文件路径）
pub use password::{Argon2Hasher, PasswordHasher, PasswordVerifier};

/// TOTP 凭证子模块（复用 `secure::totp::TotpHandler`）。
///
/// 需同时启用 `account-credential` + `secure-totp` feature。
#[cfg(all(feature = "account-credential", feature = "secure-totp"))]
pub mod totp;

/// 备份码凭证子模块。
#[cfg(feature = "account-credential")]
pub mod backup_code;

use crate::constants::DaoKeyPrefix;
use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use std::sync::Arc;

// ============================================================================
// 类型别名
// ============================================================================

/// 凭证类型标识（字符串形式，如 `"password"` / `"totp"` / `"webauthn"`）。
///
/// 使用 `&'static str` 而非 `String`：凭证类型在编译期已知，避免分配。
pub type CredentialType = &'static str;

// ============================================================================
// Credential trait（统一凭证校验接口）
// ============================================================================

/// 凭证统一 trait（吸收 keycloak CredentialModel SPI）。
///
/// 每种凭证类型（password / TOTP / WebAuthn）实现此 trait，提供统一的
/// `credential_type()` / `to_model()` / `verify()` 接口。
///
/// # 对象安全
///
/// `verify` 接收 `&str` 而非泛型（决策 D1），保证 trait 对象安全，
/// 可作 `Box<dyn Credential>` / `Arc<dyn Credential>` 使用。
///
/// # 示例
///
/// ```ignore
/// use bulwark::account::credential::{Credential, CredentialModel};
///
/// let cred: Box<dyn Credential> = /* PasswordCredential / TotpCredential */;
/// let ok = cred.verify("user-input").await?;
/// ```
#[async_trait]
pub trait Credential: Send + Sync {
    /// 凭证类型标识（如 `"password"` / `"totp"`）。
    fn credential_type(&self) -> CredentialType;

    /// 转换为存储模型（序列化用于 DAO 持久化）。
    fn to_model(&self) -> CredentialModel;

    /// 校验用户输入与存储凭证是否匹配。
    ///
    /// # 参数
    /// - `input`: 用户输入（明文密码 / TOTP code / WebAuthn challenge JSON）
    ///
    /// # 返回
    /// - `Ok(true)`: 校验通过
    /// - `Ok(false)`: 校验失败（凭证不匹配）
    /// - `Err(_)`: 校验过程出错（如哈希格式不支持、DAO 故障）
    async fn verify(&self, input: &str) -> BulwarkResult<bool>;
}

// ============================================================================
// CredentialModel（凭证存储模型）
// ============================================================================

/// 凭证存储模型（DAO 持久化结构）。
///
/// 8 字段 schema（pre-1.0 锁定，与 design.md §3.1 严格一致）。
/// 通过 `serde::Serialize` / `serde::Deserialize` 序列化为 JSON 存入 DAO。
///
/// # 字段说明
///
/// | 字段 | 类型 | 说明 |
/// |:---|:---|:---|
/// | `id` | `String` | 凭证 ID（UUID v4） |
/// | `user_id` | `String` | 用户 ID（关联 login_id） |
/// | `credential_type` | `String` | 凭证类型（`"password"` / `"totp"` / ...） |
/// | `secret_data` | `String` | 凭证数据（hash / secret / public key，JSON 编码） |
/// | `label` | `Option<String>` | 用户自定义标签（如 `"iPhone TOTP"`） |
/// | `created_at` | `i64` | 创建时间（Unix 时间戳） |
/// | `enabled` | `bool` | 是否启用 |
/// | `priority` | `i32` | 优先级（多凭证时排序，小值优先） |
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(
    feature = "account-credential-zeroize",
    derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)
)]
pub struct CredentialModel {
    /// 凭证 ID（UUID v4）。
    pub id: String,
    /// 用户 ID（关联 login_id）。
    pub user_id: String,
    /// 凭证类型（`"password"` / `"totp"` / `"webauthn"`）。
    pub credential_type: String,
    /// 凭证数据（hash / secret / public key，JSON 编码）。
    pub secret_data: String,
    /// 凭证标签（用户自定义名称，如 `"iPhone TOTP"`）。
    pub label: Option<String>,
    /// 创建时间（Unix 时间戳）。
    pub created_at: i64,
    /// 是否启用。
    pub enabled: bool,
    /// 优先级（多凭证时排序，小值优先）。
    pub priority: i32,
}

// ============================================================================
// CredentialRepository trait（凭证存储抽象）
// ============================================================================

/// 凭证存储抽象（DAO 层接口）。
///
/// 5 方法 CRUD：`create` / `find_by_user` / `find_by_user_and_type` / `update` / `delete`。
/// 由 `DaoCredentialRepository`（T006 实现）基于 `BulwarkDao` 实现，也可由业务方自定义实现。
///
/// # IDOR 防护（vuln-0004 修复）
///
/// `find_by_user` / `update` / `delete` 强制要求 `caller_login_id` 参数，由实现层验证
/// `caller_login_id` 与目标凭证的 `user_id` 一致，否则返回 `BulwarkError::NotPermission`
/// （HTTP 403 Forbidden）。`update` 额外禁止修改 `user_id` 字段（防止凭证跨用户转移）。
///
/// # DAO key 格式
///
/// `cred:{user_id}:{cred_id}`（如 `cred:alice:550e8400-...`）
///
/// # 示例
///
/// ```ignore
/// use bulwark::account::credential::{CredentialModel, CredentialRepository};
/// use std::sync::Arc;
///
/// let repo: Arc<dyn CredentialRepository> = /* DaoCredentialRepository */;
/// // caller_login_id 必须等于 user_id，否则返回 NotPermission
/// let creds = repo.find_by_user("alice", "alice").await?;
/// ```
#[async_trait]
pub trait CredentialRepository: Send + Sync {
    /// 创建凭证。
    ///
    /// # 错误
    /// - 凭证 ID 已存在：`BulwarkError::InvalidParam`
    /// - DAO 故障：透传 `BulwarkError::Dao`
    async fn create(&self, credential: CredentialModel) -> BulwarkResult<()>;

    /// 按 `user_id` 查询所有凭证（IDOR 防护：需 caller 身份校验）。
    ///
    /// 实现层必须验证 `caller_login_id == user_id`，否则返回
    /// `BulwarkError::NotPermission`。返回顺序按 `priority` 升序（小值优先）。
    ///
    /// # 错误
    /// - `caller_login_id != user_id`：`BulwarkError::NotPermission`（403 Forbidden）
    /// - DAO 故障：透传 `BulwarkError::Dao`
    async fn find_by_user(
        &self,
        caller_login_id: &str,
        user_id: &str,
    ) -> BulwarkResult<Vec<CredentialModel>>;

    /// 按 `user_id` + `credential_type` 查询凭证。
    ///
    /// 在 `find_by_user` 基础上按 `credential_type` 字段过滤。
    ///
    /// # 安全语义
    ///
    /// 此方法未显式接收 `caller_login_id`，调用方应在认证上下文中使用，
    /// 确保 `user_id` 即为当前会话主体（如 `execute_login` / `execute_mfa` 内部调用）。
    /// 默认实现 (`DaoCredentialRepository`) 内部以 `find_by_user(user_id, user_id)` 调用，
    /// 即假定 caller 即 user_id。
    async fn find_by_user_and_type(
        &self,
        user_id: &str,
        cred_type: &str,
    ) -> BulwarkResult<Vec<CredentialModel>>;

    /// 更新凭证（覆盖写，IDOR 防护：需 caller 身份校验）。
    ///
    /// 实现层必须验证 `caller_login_id` 与既有凭证的 `user_id` 一致，
    /// 且新 `credential.user_id` 不得改变（防止凭证跨用户转移），
    /// 否则返回 `BulwarkError::NotPermission`。
    ///
    /// # 错误
    /// - 凭证 ID 不存在：`BulwarkError::InvalidParam`
    /// - `caller_login_id != 既有凭证.user_id`：`BulwarkError::NotPermission`
    /// - `credential.user_id != 既有凭证.user_id`：`BulwarkError::NotPermission`（禁止转移）
    /// - DAO 故障：透传 `BulwarkError::Dao`
    async fn update(&self, caller_login_id: &str, credential: CredentialModel)
        -> BulwarkResult<()>;

    /// 删除凭证（IDOR 防护：需 caller 身份校验）。
    ///
    /// 实现层必须先定位凭证，验证 `caller_login_id` 与凭证的 `user_id` 一致，
    /// 否则返回 `BulwarkError::NotPermission`。
    ///
    /// # 错误
    /// - 凭证 ID 不存在：`BulwarkError::InvalidParam`
    /// - `caller_login_id != 凭证.user_id`：`BulwarkError::NotPermission`（403 Forbidden）
    /// - DAO 故障：透传 `BulwarkError::Dao`
    async fn delete(&self, caller_login_id: &str, credential_id: &str) -> BulwarkResult<()>;
}

// ============================================================================
// DaoCredentialRepository（基于 BulwarkDao 的默认实现）
// ============================================================================

/// 基于 `BulwarkDao` 的 `CredentialRepository` 默认实现。
///
/// 凭证以 JSON 序列化存入 DAO，key 格式严格为 `cred:{user_id}:{cred_id}`，
/// 永久存储（无 TTL，使用 `set_permanent`）。
///
/// # DAO key 格式
///
/// `cred:{user_id}:{cred_id}`（如 `cred:alice:550e8400-e29b-...`）
///
/// # 已知限制
///
/// - `find_by_user` / `find_by_user_and_type` / `delete` 依赖 `BulwarkDao::keys()`。
///   `BulwarkDaoOxcache` 当前未实现 `keys()`（返回 `NotImplemented`，详见 A-010），
///   生产环境需使用支持 `keys()` 的 DAO 后端，或由业务方维护 key 索引。
/// - `delete(caller_login_id, credential_id)` 通过扫描 `cred:*:{credential_id}` 定位
///   完整 key（`credential_id` 为 UUID v4 全局唯一，理论上仅匹配一个 key），
///   再反序列化校验 `user_id == caller_login_id` 后删除。
pub struct DaoCredentialRepository {
    dao: Arc<dyn BulwarkDao>,
}

mod repository_impl;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
