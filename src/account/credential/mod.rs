// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 凭证模型 SPI 子模块（吸收 Keycloak CredentialModel SPI）：统一凭证抽象，支持 password / TOTP / WebAuthn 等。
//!
//! 核心类型：`Credential` trait（统一校验接口）、`CredentialModel`（DAO 持久化结构，8 字段 schema）、
//! `CredentialRepository` trait（CRUD 5 方法）。`Credential::verify` 接收 `&str` 而非泛型（对象安全）；
//! `PasswordHasher` 位于 `password` 子模块。

/// 密码哈希子模块。
///
/// 提供 `PasswordHasher` trait + `Argon2Hasher` / `BcryptHasher` + `PasswordVerifier`。
#[cfg(feature = "account-credential")]
pub mod password;

// 模块重导出：通过 mod 路径访问子模块类型（避免外部代码引用具体文件路径）
#[cfg(feature = "account-credential")]
pub use password::{Argon2Hasher, PasswordHasher, PasswordVerifier};

/// TOTP 凭证子模块（复用 `secure::totp::TotpHandler`）。
///
/// 需同时启用 `account-credential` + `secure-totp` feature。
#[cfg(all(feature = "account-credential", feature = "secure-totp"))]
pub mod totp;

/// 邮箱验证码凭证子模块（复用 `secure::email::EmailVerificationService`）：`secret_data` 存邮箱地址，
/// 验证委托 `EmailVerificationService::verify_code`（KV 一次性消费 + 限速 + 异常检测）。
///
/// 需同时启用 `account-credential` + `email-verification` feature。
#[cfg(all(feature = "account-credential", feature = "email-verification"))]
pub mod email;

/// 备份码凭证子模块。
#[cfg(feature = "account-credential")]
pub mod backup_code;

use crate::constants::DaoKeyPrefix;
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use std::sync::Arc;

/// 凭证类型标识（字符串形式，如 `"password"` / `"totp"` / `"webauthn"`）。
///
/// 使用 `&'static str` 而非 `String`：凭证类型在编译期已知，避免分配。
pub type CredentialType = &'static str;

/// 凭证统一 trait（吸收 Keycloak CredentialModel SPI）。
///
/// 每种凭证类型（password / TOTP / WebAuthn）提供统一的 `credential_type()` / `to_model()` /
/// `verify()` 接口；`verify` 接收 `&str` 而非泛型，保证对象安全（可作 `Box<dyn Credential>` /
/// `Arc<dyn Credential>`）。
///
/// # 示例
///
/// ```ignore
/// use garrison::account::credential::{Credential, CredentialModel};
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

    /// 校验用户输入（明文密码 / TOTP code / WebAuthn challenge JSON）与存储凭证是否匹配；
    /// `Ok(false)` 为凭证不匹配，`Err` 为校验过程出错（哈希格式不支持、DAO 故障）。
    async fn verify(&self, input: &str) -> GarrisonResult<bool>;
}

/// 凭证存储模型（DAO 持久化结构，8 字段 schema 锁定；经 serde 序列化为 JSON 存入 DAO）。
///
/// # 安全注意（secret_data 默认不清零）
///
/// `secret_data` 存密码哈希 / TOTP secret / WebAuthn 公钥等敏感材料。`Zeroize` / `ZeroizeOnDrop`
/// 仅在启用 `credential-zeroize` feature 时派生（独立 opt-in，不随 `account-credential` 自动启用）；
/// 默认构建下 drop 后内存不清零，存在 heapdump / 冷启动残留风险，高安全场景请显式启用或在业务层
/// 自行管理生命周期。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(
    feature = "credential-zeroize",
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

/// 凭证存储抽象（DAO 层接口），CRUD 方法：`create` / `find_by_user` / `find_by_user_and_type` /
/// `update` / `delete`；默认实现 `DaoCredentialRepository` 基于 `GarrisonDao`，也可由业务方自定义。
///
/// # IDOR 防护
///
/// `find_by_user` / `update` / `delete` 强制 `caller_login_id` 参数，实现层须验证其与目标凭证
/// `user_id` 一致，否则返回 `GarrisonError::NotPermission`（403）；`update` 额外禁止修改 `user_id`
/// （防凭证跨用户转移）。
///
/// # DAO key 格式
///
/// `cred:{user_id}:{cred_id}`（如 `cred:alice:550e8400-...`）
///
/// # 示例
///
/// ```ignore
/// use garrison::account::credential::{CredentialModel, CredentialRepository};
/// use std::sync::Arc;
///
/// let repo: Arc<dyn CredentialRepository> = /* DaoCredentialRepository */;
/// // caller_login_id 必须等于 user_id，否则返回 NotPermission
/// let creds = repo.find_by_user("alice", "alice").await?;
/// ```
#[async_trait]
pub trait CredentialRepository: Send + Sync {
    /// 创建凭证；凭证 ID 已存在返回 `InvalidParam`，DAO 故障透传。
    async fn create(&self, credential: CredentialModel) -> GarrisonResult<()>;

    /// 按 `user_id` 查询所有凭证（IDOR 防护：需 caller 身份校验）。
    ///
    /// 实现层必须验证 `caller_login_id == user_id`，否则返回 `GarrisonError::NotPermission`；
    /// 返回顺序按 `priority` 升序（小值优先）。
    async fn find_by_user(
        &self,
        caller_login_id: &str,
        user_id: &str,
    ) -> GarrisonResult<Vec<CredentialModel>>;

    /// 按 `user_id` + `credential_type` 查询凭证（在 `find_by_user` 基础上按类型过滤）。
    ///
    /// # Warning
    ///
    /// 此方法未显式接收 `caller_login_id`，实现层不做 caller-vs-owner 校验：它是面向认证流程内部
    /// 的受信接口，调用方必须保证 `user_id` 即为当前会话主体（如 `execute_login` / `execute_mfa`
    /// 内部调用），透传外部可控的 `user_id` 属 IDOR 漏洞；外部查询请用
    /// [`find_by_user`](Self::find_by_user)。默认实现内部以 `find_by_user(user_id, user_id)` 调用。
    async fn find_by_user_and_type(
        &self,
        user_id: &str,
        cred_type: &str,
    ) -> GarrisonResult<Vec<CredentialModel>>;

    /// 更新凭证（覆盖写，IDOR 防护：需 caller 身份校验）。
    ///
    /// 实现层必须验证 `caller_login_id` 与既有凭证 `user_id` 一致，且新 `credential.user_id`
    /// 不得改变（防跨用户转移）；凭证 ID 不存在返回 `InvalidParam`，越权返回 `NotPermission`。
    async fn update(
        &self,
        caller_login_id: &str,
        credential: CredentialModel,
    ) -> GarrisonResult<()>;

    /// 删除凭证（IDOR 防护：需 caller 身份校验）：实现层须先定位凭证并验证 `caller_login_id`
    /// 与凭证 `user_id` 一致（否则 `NotPermission`）；凭证 ID 不存在返回 `InvalidParam`。
    async fn delete(&self, caller_login_id: &str, credential_id: &str) -> GarrisonResult<()>;
}

/// 基于 `GarrisonDao` 的 `CredentialRepository` 默认实现：凭证以 JSON 序列化存入 DAO，
/// key 严格为 `cred:{user_id}:{cred_id}`，永久存储（`set_permanent`，无 TTL）。
///
/// # 已知限制
///
/// - `find_by_user` / `find_by_user_and_type` / `delete` 依赖 `GarrisonDao::keys()`，其错误原样上抛
///   （不静默）；`GarrisonDaoOxcache` 未启用 `dao-key-index` feature 时 `keys()` 返回 `NotImplemented`，
///   生产环境需启用该 feature 或换支持 `keys()` 的后端，或自维护 key 索引。
/// - `delete` 扫描 `cred:*:{credential_id}` 定位完整 key（UUID v4 全局唯一，理论上仅匹配一个），
///   再反序列化校验 `user_id == caller_login_id` 后删除；异常多键场景逐 key 处理，先删的 key 不回滚
///   （详见 repository_impl 模块文档）。
pub struct DaoCredentialRepository {
    dao: Arc<dyn GarrisonDao>,
}

mod repository_impl;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
