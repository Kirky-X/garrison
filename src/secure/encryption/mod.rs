// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 落库敏感字段静态加密（AES-256-GCM at-rest encryption）。
//!
//! 编码格式 `enc:v1:<key_id>:<base64(nonce|ciphertext)>`，AAD 绑定
//! `garrison:{tenant}:{table}:{key}`（对齐 authelia encryption_aad.go:78-85）：
//! 密文挪到其他行/列（AAD 不匹配）或换 key（key_id 不匹配）解密即失败，
//! 防挪用重放。加解密失败一律显性报错，不返回明文占位。
//! token 类命名空间的落库 key 名同步摘要化（裸 bearer token 不得留在 key 名）。
//!
//! - [`crypto_value`]：编解码 + AES-256-GCM 原语
//! - [`cipher`]：密钥注入（多 key_id）+ fail-closed 装配 + 迁移期双读门面
//! - [`dao`]：`GarrisonDao` 透明加解密装饰器（key 名摘要化、写全加密、读双读）
//! - [`rekey`]：change-key / check-key 运维接口（结构化报告，逐行显性）
//!
//! # 密钥注入（生产路径）
//!
//! [`FieldCipher::from_key_entries`]：从 (key_id, hex32) 配置表目装配
//! ——生产注入面（如 auth_server `GARRISON_FIELD_ENCRYPTION_KEYS`）。
//! `config-encryption` feature 下另有 confers `KeyRegistry` 适配器
//! [`ConfersFieldKeyProvider`]（version 即 key_id）。
//! 启用 `field-encryption` 未配密钥 → 装配期 fail-closed Err（启动失败）。
//!
//! # 装配（透明接线）
//!
//! ```ignore
//! let cipher = Arc::new(FieldCipher::from_key_entries(&entries)?);
//! let dao = Arc::new(FieldEncryptionDao::new(raw_dao, cipher, "tenant")?);
//! // dao 传入 GarrisonManagerBuilder::dao(...)
//! ```

mod cipher;
mod crypto_value;
mod dao;
mod rekey;

pub use cipher::{FieldCipher, FieldKeyProvider, StaticFieldKeyProvider};
pub use crypto_value::{AadBinding, CryptoValue, KEY_LEN, NONCE_LEN};
pub use dao::{is_digest_form, FieldEncryptionDao, DIGEST_TABLES, SENSITIVE_TABLES};
pub use rekey::{ChangeKeyReport, CheckKeyReport};

/// config-encryption 既有密钥设施（confers KeyRegistry）适配器。
///
/// 仅在 `config-encryption` feature 启用时存在（`production` 组合不含该
/// feature；生产注入路径为 [`FieldCipher::from_key_entries`] 配置面）。
#[cfg(feature = "config-encryption")]
pub use cipher::ConfersFieldKeyProvider;
