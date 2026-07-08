//! 凭证模型 SPI 子模块（v0.6.0 新增，吸收 keycloak CredentialModel SPI）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 提供统一凭证抽象，支持 password / TOTP / WebAuthn（v0.7+）等多种凭证类型。
//! 详见 spec `credential-model`。

/// 密码哈希子模块（v0.6.0 从 secure/password/ 迁移）。
///
/// 提供 `PasswordHasher` trait + `Argon2Hasher` / `BcryptHasher` + `PasswordVerifier`。
pub mod password;

// T003 将在此实现 Credential trait + CredentialRepository
// T004 将在此实现 PasswordCredential
// T005 将在此实现 TotpCredential
// T006 将在此实现 DaoCredentialRepository

// 临时占位类型，供 T001 编译测试引用（T003 替换为完整实现）
/// 凭证存储模型（占位，T003 实现完整字段）。
#[derive(Debug, Clone)]
pub struct CredentialModel;
