// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! [`CryptoValue`] 编解码与 AES-256-GCM 原语。
//!
//! 落库敏感字段的密文载体，编码格式：
//!
//! ```text
//! enc:v1:<key_id>:<base64(nonce|ciphertext)>
//! ```
//!
//! - `nonce`：12 字节随机（每值独立，直读 OS CSPRNG）
//! - `ciphertext`：AES-256-GCM 密文 + 16 字节认证 tag（aead crate 拼接语义）
//! - AAD 绑定 `garrison:{tenant}:{table}:{key}`：密文挪到其他行/列
//!   （AAD 不匹配）或换钥解密即失败，防挪用重放
//!   （对齐 authelia encryption_aad.go:78-85）
//!
//! `key_id` 不得含 `:`（会破坏四段式格式解析）且不得为空，`seal`/`decode` 双侧校验。

use crate::error::{GarrisonError, GarrisonResult};
use aes_gcm::aead::{Aead, Nonce, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use base64::{engine::general_purpose::STANDARD, Engine};

/// CryptoValue 编码前缀（含版本段 `v1`）。
pub const CRYPTO_VALUE_PREFIX: &str = "enc:v1:";

/// AES-256 密钥长度（字节）。
pub const KEY_LEN: usize = 32;

/// 测试钥材单点（非退化：字节递增序列 `seed + i`；装配期弱钥检测会拒绝
/// 单字节重复形态）。跨测试模块共享，避免同一材料多份 const 块漂移。
#[cfg(test)]
pub(crate) const fn test_key(seed: u8) -> [u8; KEY_LEN] {
    let mut k = [0u8; KEY_LEN];
    let mut i = 0;
    while i < KEY_LEN {
        k[i] = seed.wrapping_add(i as u8);
        i += 1;
    }
    k
}

/// GCM nonce 长度（字节，NIST SP 800-38D §5.2.1.1 推荐 96 bit）。
pub const NONCE_LEN: usize = 12;

/// AAD 绑定三元组：`garrison:{tenant}:{table}:{key}`。
///
/// - `tenant`：租户（单租户部署用 `"default"`）
/// - `table`：逻辑表 / DAO key 前缀（如 `oauth2:atoken`）
/// - `key`：行标识（如 DAO key 去掉前缀后的 id）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AadBinding {
    /// 租户标识。
    pub tenant: String,
    /// 逻辑表 / 命名空间标识。
    pub table: String,
    /// 行标识。
    pub key: String,
}

impl AadBinding {
    /// 构造 AAD 绑定三元组。
    pub fn new(
        tenant: impl Into<String>,
        table: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        Self {
            tenant: tenant.into(),
            table: table.into(),
            key: key.into(),
        }
    }

    /// 序列化为 AAD 字节串 `garrison:{tenant}:{table}:{key}`。
    fn aad_bytes(&self) -> Vec<u8> {
        format!("garrison:{}:{}:{}", self.tenant, self.table, self.key).into_bytes()
    }
}

/// 密文载体：`enc:v1:<key_id>:<base64(nonce|ciphertext)>` 的结构化形态。
///
/// `ciphertext` 含末尾 16 字节 GCM 认证 tag（`Aead::encrypt` 的拼接语义）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoValue {
    /// 加密所用密钥的标识（解密按此取钥，支持多 key_id 共存）。
    pub key_id: String,
    /// 12 字节随机 nonce。
    pub nonce: [u8; NONCE_LEN],
    /// 密文 + 认证 tag。
    pub ciphertext: Vec<u8>,
}

impl CryptoValue {
    /// 编码前缀（结构化别名，双读判定用）。
    pub const PREFIX: &str = CRYPTO_VALUE_PREFIX;

    /// 加密：随机 nonce + AES-256-GCM（AAD 绑定）。
    ///
    /// # 参数
    /// - `key_id`: 密钥标识（非空、不含 `:`，违反即显性报错）
    /// - `key`: 32 字节 AES-256 密钥
    /// - `aad`: AAD 绑定三元组
    /// - `plaintext`: 明文字节
    pub fn seal(
        key_id: &str,
        key: &[u8; KEY_LEN],
        aad: &AadBinding,
        plaintext: &[u8],
    ) -> GarrisonResult<Self> {
        validate_key_id(key_id, "seal")?;
        let mut nonce = [0u8; NONCE_LEN];
        // 直读 OS CSPRNG（与 oauth2 授权码 / CSRF 路径同一安全立场）
        getrandom::fill(&mut nonce).expect("OS CSPRNG 不可用");
        let cipher = Aes256Gcm::new(key_view(key));
        let ciphertext = cipher
            .encrypt(
                nonce_view(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad.aad_bytes(),
                },
            )
            .map_err(|e| GarrisonError::Internal(format!("secure-field-encryption-seal::{e}")))?;
        Ok(Self {
            key_id: key_id.to_string(),
            nonce,
            ciphertext,
        })
    }

    /// 解密：AAD 不匹配 / 密钥错误 / tag 损坏一律显性报错（不返回明文占位）。
    pub fn open(&self, key: &[u8; KEY_LEN], aad: &AadBinding) -> GarrisonResult<Vec<u8>> {
        let cipher = Aes256Gcm::new(key_view(key));
        cipher
            .decrypt(
                nonce_view(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad.aad_bytes(),
                },
            )
            .map_err(|_| {
                GarrisonError::Internal(
                    "secure-field-encryption-open::aad-or-key-or-tag-mismatch".to_string(),
                )
            })
    }

    /// 编码为 `enc:v1:<key_id>:<base64(nonce|ciphertext)>`。
    pub fn encode(&self) -> String {
        let mut payload = Vec::with_capacity(NONCE_LEN + self.ciphertext.len());
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&self.ciphertext);
        format!(
            "{}{}:{}",
            CRYPTO_VALUE_PREFIX,
            self.key_id,
            STANDARD.encode(payload)
        )
    }

    /// 解码四段式格式（前缀 / 版本 / key_id / base64 载荷逐项显性校验）。
    pub fn decode(encoded: &str) -> GarrisonResult<Self> {
        let rest = encoded
            .strip_prefix(CRYPTO_VALUE_PREFIX)
            .ok_or_else(|| decode_err("missing-enc-v1-prefix"))?;
        let (key_id, payload_b64) = rest
            .split_once(':')
            .ok_or_else(|| decode_err("missing-key-id-segment"))?;
        validate_key_id(key_id, "decode")?;
        if payload_b64.is_empty() {
            return Err(decode_err("empty-payload"));
        }
        let payload = STANDARD
            .decode(payload_b64)
            .map_err(|e| decode_err(&format!("base64:{}", e)))?;
        if payload.len() < NONCE_LEN + 16 {
            return Err(decode_err(&format!(
                "payload-too-short:len={}",
                payload.len()
            )));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&payload[..NONCE_LEN]);
        Ok(Self {
            key_id: key_id.to_string(),
            nonce,
            ciphertext: payload[NONCE_LEN..].to_vec(),
        })
    }
}

/// `seal` / `decode` / 配置面共用的 key_id 校验：非空且不含 `:`（格式分隔符保留）。
pub(crate) fn validate_key_id(key_id: &str, op: &str) -> GarrisonResult<()> {
    if key_id.is_empty() {
        return Err(op_err(op, "empty-key-id"));
    }
    if key_id.contains(':') {
        return Err(op_err(op, "key-id-contains-colon"));
    }
    Ok(())
}

fn decode_err(detail: &str) -> GarrisonError {
    GarrisonError::Internal(format!("secure-field-encryption-decode::{detail}"))
}

fn op_err(op: &str, detail: &str) -> GarrisonError {
    GarrisonError::Internal(format!("secure-field-encryption-{op}::{detail}"))
}

/// `&[u8; 32]` → `&Key<Aes256Gcm>` 视图（长度静态匹配，转换不会失败）。
fn key_view(key: &[u8; KEY_LEN]) -> &Key<Aes256Gcm> {
    key.as_slice()
        .try_into()
        .expect("AES-256 密钥长度静态固定为 32 字节")
}

/// `&[u8; 12]` → `&Nonce<Aes256Gcm>` 视图（长度静态匹配，转换不会失败）。
fn nonce_view(nonce: &[u8; NONCE_LEN]) -> &Nonce<Aes256Gcm> {
    nonce
        .as_slice()
        .try_into()
        .expect("GCM nonce 长度静态固定为 12 字节")
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = test_key(7);
    const OTHER_KEY: [u8; KEY_LEN] = test_key(9);

    fn row_aad(row: &str) -> AadBinding {
        AadBinding::new("tenant-1", "oauth2:atoken", row)
    }

    /// roundtrip：seal → encode → decode → open 还原明文；同明文两次 seal nonce 独立。
    #[test]
    fn roundtrip_preserves_plaintext() {
        let v1 = CryptoValue::seal("k1", &KEY, &row_aad("row-1"), b"secret-value").unwrap();
        let decoded = CryptoValue::decode(&v1.encode()).unwrap();
        let plaintext = decoded.open(&KEY, &row_aad("row-1")).unwrap();
        assert_eq!(plaintext, b"secret-value");

        let v2 = CryptoValue::seal("k1", &KEY, &row_aad("row-1"), b"secret-value").unwrap();
        assert_ne!(v1.nonce, v2.nonce, "每值 nonce 必须独立随机");
    }

    /// 密文挪到他行（AAD 的 key 段不匹配）解密失败；挪到他表/他租户同理。
    #[test]
    fn ciphertext_moved_to_other_row_fails() {
        let v = CryptoValue::seal("k1", &KEY, &row_aad("row-1"), b"secret-value").unwrap();
        let decoded = CryptoValue::decode(&v.encode()).unwrap();

        let moved_row = decoded.open(&KEY, &row_aad("row-2")).unwrap_err();
        assert!(matches!(moved_row, GarrisonError::Internal(_)));

        let moved_table =
            decoded.open(&KEY, &AadBinding::new("tenant-1", "oauth2:client", "row-1"));
        assert!(moved_table.is_err());

        let moved_tenant =
            decoded.open(&KEY, &AadBinding::new("tenant-2", "oauth2:atoken", "row-1"));
        assert!(moved_tenant.is_err());
    }

    /// key_id 不匹配（用错误钥材解密）失败。
    #[test]
    fn wrong_key_material_fails() {
        let v = CryptoValue::seal("k1", &KEY, &row_aad("row-1"), b"secret-value").unwrap();
        let err = v.open(&OTHER_KEY, &row_aad("row-1")).unwrap_err();
        assert!(matches!(err, GarrisonError::Internal(_)));
    }

    /// 编码格式符合 `enc:v1:<key_id>:<base64(nonce|ciphertext)>`：
    /// 三段可见、载荷 base64 可解、长度 = nonce + 明文 + tag。
    #[test]
    fn encode_format_matches_spec() {
        let plaintext = b"secret-value";
        let v = CryptoValue::seal("k1", &KEY, &row_aad("row-1"), plaintext).unwrap();
        let encoded = v.encode();

        assert!(encoded.starts_with("enc:v1:"));
        let rest = encoded.strip_prefix("enc:v1:").unwrap();
        let (key_id, payload_b64) = rest.split_once(':').unwrap();
        assert_eq!(key_id, "k1");

        use base64::Engine as _;
        let payload = STANDARD.decode(payload_b64).unwrap();
        assert_eq!(payload.len(), NONCE_LEN + plaintext.len() + 16);
        assert_eq!(&payload[..NONCE_LEN], &v.nonce);
    }

    /// decode 对畸形输入逐项显性拒绝（前缀/版本/空 key_id/含冒号 key_id/坏 base64/过短载荷）。
    #[test]
    fn decode_rejects_malformed_values() {
        let valid = CryptoValue::seal("k1", &KEY, &row_aad("row-1"), b"x")
            .unwrap()
            .encode();

        assert!(CryptoValue::decode("plain-text-value").is_err());
        assert!(CryptoValue::decode("enc:v2:k1:AAAA").is_err());
        assert!(CryptoValue::decode("enc:v1::AAAA").is_err());
        assert!(CryptoValue::decode("enc:v1:k:1:AAAA").is_err());
        assert!(CryptoValue::decode("enc:v1:k1:not-base64!!!").is_err());
        assert!(CryptoValue::decode("enc:v1:k1:AAAA").is_err());
        // 完整合法编码必须可解（对照项）
        assert!(CryptoValue::decode(&valid).is_ok());
    }

    /// seal 对非法 key_id（空 / 含冒号）显性报错。
    #[test]
    fn seal_rejects_invalid_key_id() {
        assert!(CryptoValue::seal("", &KEY, &row_aad("r"), b"x").is_err());
        assert!(CryptoValue::seal("k:1", &KEY, &row_aad("r"), b"x").is_err());
    }
}
