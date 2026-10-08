// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 密钥注入与字段加解密门面。
//!
//! 密钥来源抽象为 [`FieldKeyProvider`]（按 key_id 取钥 + 主钥 id），多 key_id
//! 共存：密文中嵌入加密所用的 key_id，解密按嵌入 id 取钥——轮换期间旧密文
//! 仍可解。注入路径二选一：
//! - **生产配置面**（不依赖额外 feature）：[`FieldCipher::from_key_entries`]
//!   从 (key_id, hex32) 配置表目装配（如 auth_server
//!   `GARRISON_FIELD_ENCRYPTION_KEYS` 环境变量），内部用
//!   [`StaticFieldKeyProvider`]
//! - **config-encryption 既有密钥设施**（`config-encryption` feature 门控）：
//!   [`ConfersFieldKeyProvider`] 包装 confers `KeyRegistry`（version 即 key_id）
//!
//! fail-closed：启用 `field-encryption` 但未配置任何密钥时，装配期
//! （[`FieldCipher::new`] / [`FieldCipher::from_key_entries`]）即报错
//! （启动失败），绝不允许无钥明文运行。

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{GarrisonError, GarrisonResult};

use super::crypto_value::{AadBinding, CryptoValue, KEY_LEN};

/// 字段加密密钥提供者：按 key_id 取 32 字节 AES-256 密钥。
///
/// `key_for` 对未知 key_id / 非法长度必须显性报错（fail-closed，不返回占位钥）。
pub trait FieldKeyProvider: Send + Sync {
    /// 按 key_id 取密钥（恰好 32 字节）。
    fn key_for(&self, key_id: &str) -> GarrisonResult<[u8; KEY_LEN]>;

    /// 当前主钥 id（新写入一律用主钥加密）。
    fn primary_key_id(&self) -> GarrisonResult<String>;
}

/// [`FieldKeyProvider`] 的静态实现：内存 key_id → 密钥表。
///
/// [`FieldCipher::from_key_entries`] 生产配置面的底层载体（配置解析产物），
/// 亦供测试与直连装配。首个注册项为主钥；
/// [`StaticFieldKeyProvider::with_primary`] 可切换（主钥切换后旧密文仍按
/// 嵌入 key_id 可解）。
#[derive(Debug, Clone)]
pub struct StaticFieldKeyProvider {
    keys: HashMap<String, [u8; KEY_LEN]>,
    primary: String,
}

impl StaticFieldKeyProvider {
    /// 从 (key_id, key) 列表构建；列表非空且 key_id 互异，首项为主钥。
    pub fn new(keys: Vec<(String, [u8; KEY_LEN])>) -> GarrisonResult<Self> {
        let primary = keys
            .first()
            .map(|(id, _)| id.clone())
            .ok_or_else(|| config_err("no-keys-configured"))?;
        let mut map = HashMap::with_capacity(keys.len());
        for (idx, (id, key)) in keys.into_iter().enumerate() {
            if is_degenerate_key(&key) {
                // 主钥（首项，新写入一律使用）严格拒绝；非主钥（仅解密存量密文）
                // 降级 warn 放行——否则含退役弱钥的部署无法经 garrison-cli
                // change-key 携旧钥重加密后摘除（迁移出口被 fail-closed 锁死）。
                if idx == 0 {
                    return Err(config_err(&format!("weak-key:{id}")));
                }
                tracing::warn!(
                    key_id = %id,
                    "field-encryption: non-primary key is degenerate (single repeated byte);                      allowed for legacy decryption only — rotate it away via change-key"
                );
            }
            if map.insert(id.clone(), key).is_some() {
                return Err(config_err(&format!("duplicate-key-id:{id}")));
            }
        }
        Ok(Self { keys: map, primary })
    }

    /// 切换主钥（目标 key_id 必须已注册且非退化钥）。
    pub fn with_primary(mut self, key_id: &str) -> GarrisonResult<Self> {
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| config_err(&format!("key-not-found:{key_id}")))?;
        if is_degenerate_key(key) {
            return Err(config_err(&format!("weak-primary-key:{key_id}")));
        }
        self.primary = key_id.to_string();
        Ok(self)
    }
}

impl FieldKeyProvider for StaticFieldKeyProvider {
    fn key_for(&self, key_id: &str) -> GarrisonResult<[u8; KEY_LEN]> {
        self.keys
            .get(key_id)
            .copied()
            .ok_or_else(|| config_err(&format!("key-not-found:{key_id}")))
    }

    fn primary_key_id(&self) -> GarrisonResult<String> {
        Ok(self.primary.clone())
    }
}

/// 退化钥检测（confers `is_weak_key` 的等价本地检查：上游该函数所在模块
/// `pub(crate)` 不可跨 crate 调用）：`[u8; KEY_LEN]` 非空，退化形态即
/// **单字节重复**（全零 / 全 0xFF / 单字符填充）——此类钥熵不足，
/// 装配期 fail-fast 而非静默接受。
fn is_degenerate_key(key: &[u8; KEY_LEN]) -> bool {
    key.iter().all(|&b| b == key[0])
}

/// 字段加解密门面：多 key_id 取钥 + 迁移期双读。
///
/// - `encrypt`：主钥加密，产出 `enc:v1:<key_id>:<...>` 编码串
/// - `decrypt`：双读——有 `enc:v1:` 前缀则按嵌入 key_id 取钥解密；
///   无前缀（迁移期明文遗留行）原样返回
#[derive(Clone)]
pub struct FieldCipher {
    provider: Arc<dyn FieldKeyProvider>,
}

impl FieldCipher {
    /// 装配：探测主钥可取（未配密钥 / 取钥失败 → 装配期显性失败）；
    /// 主钥为退化形态（单字节重复）同样装配期拒绝——静态 provider 已在
    /// 注册时逐钥拒绝，此处兜底自定义 provider。
    pub fn new(provider: Arc<dyn FieldKeyProvider>) -> GarrisonResult<Self> {
        let primary = provider.primary_key_id()?;
        let primary_key = provider.key_for(&primary)?;
        if is_degenerate_key(&primary_key) {
            return Err(config_err(&format!("weak-primary-key:{primary}")));
        }
        Ok(Self { provider })
    }

    /// 生产配置面装配：从 (key_id, hex 编码 32 字节钥材) 表目构建。
    ///
    /// 校验逐项显性：表目非空、key_id 非空且不含 `:`、hex 可解且恰 32 字节
    /// （64 个 hex 字符）、key_id 互异。任一违规即装配失败（启动期 fail-closed）。
    /// 首项为主钥。
    pub fn from_key_entries(entries: &[(String, String)]) -> GarrisonResult<Self> {
        if entries.is_empty() {
            return Err(config_err("no-keys-configured"));
        }
        let mut keys = Vec::with_capacity(entries.len());
        for (key_id, key_hex) in entries {
            super::crypto_value::validate_key_id(key_id, "config")?;
            let decoded = hex_decode_32(key_hex)
                .ok_or_else(|| config_err(&format!("key-hex-invalid:{key_id}")))?;
            keys.push((key_id.clone(), decoded));
        }
        let provider = StaticFieldKeyProvider::new(keys)?;
        FieldCipher::new(Arc::new(provider))
    }

    /// 当前主钥 id（运维 change-key 幂等跳过判定用）。
    pub fn primary_key_id(&self) -> GarrisonResult<String> {
        self.provider.primary_key_id()
    }

    /// 主钥加密并编码。
    pub fn encrypt(&self, aad: &AadBinding, plaintext: &str) -> GarrisonResult<String> {
        let key_id = self.provider.primary_key_id()?;
        let key = self.provider.key_for(&key_id)?;
        Ok(CryptoValue::seal(&key_id, &key, aad, plaintext.as_bytes())?.encode())
    }

    /// 双读解密：明文遗留行原样返回；`enc:` 行按嵌入 key_id 取钥解密。
    pub fn decrypt(&self, aad: &AadBinding, stored: &str) -> GarrisonResult<String> {
        if !stored.starts_with(CryptoValue::PREFIX) {
            return Ok(stored.to_string());
        }
        let value = CryptoValue::decode(stored)?;
        let key = self.provider.key_for(&value.key_id)?;
        let plaintext = value.open(&key, aad)?;
        String::from_utf8(plaintext)
            .map_err(|e| GarrisonError::Internal(format!("secure-field-encryption-utf8::{e}")))
    }
}

/// config-encryption 既有密钥设施（confers [`KeyRegistry`]）适配器。
///
/// confers KeyRegistry 的 version 即 garrison 的 key_id；密钥材料必须恰好
/// 32 字节（AES-256），非 32 字节显性报错。
#[cfg(feature = "config-encryption")]
pub struct ConfersFieldKeyProvider {
    registry: Arc<confers::secret::KeyRegistry>,
}

#[cfg(feature = "config-encryption")]
impl ConfersFieldKeyProvider {
    /// 包装既有 confers KeyRegistry。
    pub fn new(registry: Arc<confers::secret::KeyRegistry>) -> Self {
        Self { registry }
    }
}

#[cfg(feature = "config-encryption")]
impl FieldKeyProvider for ConfersFieldKeyProvider {
    fn key_for(&self, key_id: &str) -> GarrisonResult<[u8; KEY_LEN]> {
        let bytes = self
            .registry
            .get_key(key_id)
            .map_err(|e| GarrisonError::Internal(format!("secure-field-encryption-config::{e}")))?;
        let key: [u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| config_err(&format!("key-length:got={}", bytes.len())))?;
        Ok(key)
    }

    fn primary_key_id(&self) -> GarrisonResult<String> {
        self.registry
            .get_primary_key()
            .map(|(version, _)| version)
            .map_err(|e| GarrisonError::Internal(format!("secure-field-encryption-config::{e}")))
    }
}

fn config_err(detail: &str) -> GarrisonError {
    GarrisonError::Config(format!("secure-field-encryption-config::{detail}"))
}

/// hex 字符串 → 32 字节钥材（非 64 位 hex / 非 hex 字符返回 None）。
fn hex_decode_32(s: &str) -> Option<[u8; KEY_LEN]> {
    if s.len() != KEY_LEN * 2 {
        return None;
    }
    let mut out = [0u8; KEY_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试钥材（非退化单点：`crypto_value::test_key`，seed 1/2）。
    const K1: [u8; KEY_LEN] = crate::secure::encryption::crypto_value::test_key(1);
    const K2: [u8; KEY_LEN] = crate::secure::encryption::crypto_value::test_key(2);

    /// seed 的 hex 表达（与 [`crate::secure::encryption::crypto_value::test_key`] 同源）。
    fn key_hex(seed: u8) -> String {
        crate::secure::encryption::crypto_value::test_key(seed)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn provider(primary_k1: bool) -> Arc<dyn FieldKeyProvider> {
        let p = StaticFieldKeyProvider::new(vec![("k1".to_string(), K1), ("k2".to_string(), K2)])
            .unwrap();
        let p = if primary_k1 {
            p
        } else {
            p.with_primary("k2").unwrap()
        };
        Arc::new(p)
    }

    fn aad() -> AadBinding {
        AadBinding::new("tenant-1", "oauth2:atoken", "row-1")
    }

    /// 多 key_id：主钥切换后新写入带新 key_id，旧密文按嵌入 key_id 仍可解。
    #[test]
    fn multi_key_id_lookup_and_primary_rotation() {
        let shared = provider(true);
        let cipher = FieldCipher::new(shared.clone()).unwrap();

        let old = cipher.encrypt(&aad(), "secret-v1").unwrap();
        assert!(old.starts_with("enc:v1:k1:"), "主钥 k1 加密: {old}");

        // 主钥切换 k1 → k2（轮换中段：两把钥共存）
        let rotated = Arc::new(
            StaticFieldKeyProvider::new(vec![("k1".to_string(), K1), ("k2".to_string(), K2)])
                .unwrap()
                .with_primary("k2")
                .unwrap(),
        );
        let rotated_cipher = FieldCipher::new(rotated).unwrap();
        let new = rotated_cipher.encrypt(&aad(), "secret-v2").unwrap();
        assert!(new.starts_with("enc:v1:k2:"), "切换后主钥 k2 加密: {new}");

        // 旧密文（k1）仍可解（按嵌入 key_id 取钥）
        assert_eq!(rotated_cipher.decrypt(&aad(), &old).unwrap(), "secret-v1");
        assert_eq!(cipher.decrypt(&aad(), &new).unwrap(), "secret-v2");
    }

    /// 未知 key_id 的密文显性报错（不返回明文占位）。
    #[test]
    fn unknown_key_id_fails_explicitly() {
        let cipher = FieldCipher::new(provider(true)).unwrap();
        let value = CryptoValue::seal("k9", &[3u8; KEY_LEN], &aad(), b"x")
            .unwrap()
            .encode();
        let err = cipher.decrypt(&aad(), &value).unwrap_err();
        assert!(matches!(err, GarrisonError::Config(_)), "got: {err:?}");
    }

    /// 未配密钥 → 装配 fail-closed Err（启动期失败，不进入明文降级运行）。
    #[test]
    fn missing_key_configuration_fails_closed() {
        let empty = StaticFieldKeyProvider::new(vec![]).unwrap_err();
        assert!(matches!(empty, GarrisonError::Config(_)));
    }

    /// 生产配置面 `from_key_entries`：合法 hex32 表目装配可用（首项主钥）；
    /// 空表目 / 坏 hex / 长度非 32 字节 / 含冒号 key_id 逐项显性拒绝。
    #[test]
    fn from_key_entries_config_surface() {
        let hex1 = key_hex(1);
        let hex2 = key_hex(2);
        let entries = vec![("k1".to_string(), hex1.clone()), ("k2".to_string(), hex2)];
        let cipher = FieldCipher::from_key_entries(&entries).unwrap();
        assert_eq!(cipher.primary_key_id().unwrap(), "k1");
        let stored = cipher.encrypt(&aad(), "secret").unwrap();
        assert_eq!(cipher.decrypt(&aad(), &stored).unwrap(), "secret");

        // k2 的钥材与 StaticFieldKeyProvider 直接装配一致（同一 hex 表达）
        let direct = FieldCipher::new(Arc::new(
            StaticFieldKeyProvider::new(vec![("k1".to_string(), K1), ("k2".to_string(), K2)])
                .unwrap(),
        ))
        .unwrap();
        assert_eq!(
            direct.decrypt(&aad(), &stored).unwrap(),
            "secret",
            "from_key_entries 与直连装配钥材一致"
        );

        assert!(FieldCipher::from_key_entries(&[]).is_err());
        assert!(FieldCipher::from_key_entries(&[("k".to_string(), "zz".repeat(32))]).is_err());
        assert!(FieldCipher::from_key_entries(&[("k".to_string(), "01".repeat(31))]).is_err());
        assert!(FieldCipher::from_key_entries(&[("k:1".to_string(), hex1)]).is_err());
    }

    /// 迁移期双读：无 `enc:v1:` 前缀的明文遗留行原样返回。
    #[test]
    fn decrypt_passthrough_plaintext_legacy_row() {
        let cipher = FieldCipher::new(provider(true)).unwrap();
        assert_eq!(
            cipher.decrypt(&aad(), "plain-legacy").unwrap(),
            "plain-legacy"
        );
        assert_eq!(cipher.decrypt(&aad(), "").unwrap(), "");
    }

    /// roundtrip（经门面）：encrypt 产出 enc: 编码，decrypt 还原；同 AAD 才可解。
    #[test]
    fn cipher_roundtrip_binds_aad() {
        let cipher = FieldCipher::new(provider(true)).unwrap();
        let stored = cipher.encrypt(&aad(), "secret-value").unwrap();
        assert_eq!(cipher.decrypt(&aad(), &stored).unwrap(), "secret-value");

        let other_row = AadBinding::new("tenant-1", "oauth2:atoken", "row-2");
        assert!(cipher.decrypt(&other_row, &stored).is_err());
    }

    /// confers KeyRegistry 适配器：注册两把 32 字节钥，按 version（key_id）取钥、
    /// 主钥切换跟随；非 32 字节钥材显性报错。
    #[cfg(feature = "config-encryption")]
    #[test]
    fn confers_registry_adapter_resolves_keys() {
        use confers::secret::{KeyRegistry, KeyRotationConfig, SecretBytes};

        let registry = Arc::new(KeyRegistry::new(KeyRotationConfig::default()));
        registry
            .register_key(
                "v1".to_string(),
                SecretBytes::new(crate::secure::encryption::crypto_value::test_key(3).to_vec()),
                true,
            )
            .unwrap();
        registry
            .register_key(
                "v2".to_string(),
                SecretBytes::new(crate::secure::encryption::crypto_value::test_key(4).to_vec()),
                false,
            )
            .unwrap();

        let adapter = ConfersFieldKeyProvider::new(registry.clone());
        assert_eq!(adapter.primary_key_id().unwrap(), "v1");
        assert_eq!(
            adapter.key_for("v1").unwrap(),
            crate::secure::encryption::crypto_value::test_key(3)
        );
        assert_eq!(
            adapter.key_for("v2").unwrap(),
            crate::secure::encryption::crypto_value::test_key(4)
        );
        assert!(adapter.key_for("v-missing").is_err());

        // 非 32 字节钥材显性拒绝（AES-256 硬约束）
        registry
            .register_key("short".to_string(), SecretBytes::new(vec![1u8; 16]), false)
            .unwrap();
        assert!(adapter.key_for("short").is_err());
    }

    // ========================================================================
    // 退化密钥 fail-fast（confers is_weak_key 的等价本地检查：
    // 上游该函数所在模块 pub(crate) 不可跨 crate 调用）
    // ========================================================================

    /// 全零（单字节重复）钥被 StaticFieldKeyProvider::new 拒绝，错误含 key_id。
    #[test]
    fn static_provider_rejects_all_zero_key() {
        let err =
            StaticFieldKeyProvider::new(vec![("k1".to_string(), [0u8; KEY_LEN])]).unwrap_err();
        assert!(
            matches!(&err, GarrisonError::Config(m) if m.contains("weak-key:k1")),
            "全零钥应被拒绝且错误含 key_id，实际: {err:?}"
        );
    }

    /// 单字节重复钥（全 0xFF 填充）同样被拒绝。
    #[test]
    fn static_provider_rejects_repeated_byte_fill() {
        let err =
            StaticFieldKeyProvider::new(vec![("kf".to_string(), [0xFFu8; KEY_LEN])]).unwrap_err();
        assert!(
            matches!(&err, GarrisonError::Config(m) if m.contains("weak-key:kf")),
            "单字节重复填充钥应被拒绝，实际: {err:?}"
        );
    }

    /// 非主钥的退化钥降级 warn 放行（保留退役弱钥的解密与 change-key 轮换出口）；
    /// 但它不得被提升为主钥。
    #[test]
    fn weak_non_primary_key_allowed_but_not_promotable() {
        let provider = StaticFieldKeyProvider::new(vec![
            ("k1".to_string(), K1),
            ("k2".to_string(), [3u8; KEY_LEN]),
        ])
        .expect("非主钥退化钥应放行（warn）");
        assert_eq!(provider.key_for("k2").unwrap(), [3u8; KEY_LEN]);

        let err = provider.with_primary("k2").unwrap_err();
        assert!(
            matches!(&err, GarrisonError::Config(m) if m.contains("weak-primary-key:k2")),
            "退化钥不得提升为主钥，实际: {err:?}"
        );
    }

    /// 配置面 hex 表达的单字节重复键（全零 hex）被拒绝。
    #[test]
    fn from_key_entries_rejects_repeated_byte_hex() {
        let err = match FieldCipher::from_key_entries(&[("kz".to_string(), "00".repeat(32))]) {
            Err(e) => e,
            Ok(_) => panic!("全零 hex 钥应被拒绝"),
        };
        assert!(
            matches!(&err, GarrisonError::Config(m) if m.contains("weak-key:kz")),
            "全零 hex 钥应被拒绝，实际: {err:?}"
        );
    }

    /// 自定义 provider 返回退化主钥时 FieldCipher::new 拒绝（防御非静态 provider 路径）。
    #[test]
    fn field_cipher_rejects_degenerate_primary_from_custom_provider() {
        struct ZeroProvider;
        impl FieldKeyProvider for ZeroProvider {
            fn key_for(&self, _key_id: &str) -> GarrisonResult<[u8; KEY_LEN]> {
                Ok([0u8; KEY_LEN])
            }
            fn primary_key_id(&self) -> GarrisonResult<String> {
                Ok("zp".to_string())
            }
        }
        let err = match FieldCipher::new(Arc::new(ZeroProvider)) {
            Err(e) => e,
            Ok(_) => panic!("退化主钥应被拒绝"),
        };
        assert!(
            matches!(&err, GarrisonError::Config(m) if m.contains("weak-primary-key:zp")),
            "自定义 provider 的退化主钥应被拒绝，实际: {err:?}"
        );
    }
}
