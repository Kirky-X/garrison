// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `GarrisonDao` 透明加解密装饰器。
//!
//! 包装任意 `GarrisonDao`，对敏感命名空间（key 前缀）实施静态加密：
//! - **key 名摘要化**：token 类命名空间（`oauth2:atoken:` / `oauth2:rtoken:` /
//!   `oauth2:codeused:`）的 key 名本身承载 bearer 凭据（裸 token / 授权码），
//!   落库前将 key 余段摘要为 SHA-256 hex——DB 泄露无法从 key 名回收凭据重放。
//!   读写两侧经同一装饰器派生，调用方继续用原 key（透传语义不变）。
//! - **写路径全加密**（`set` / `set_permanent` / `update` / `set_if_absent`）：
//!   敏感命名空间落库值恒为 `enc:v1:<key_id>:<base64(nonce|ciphertext)>`
//! - **读路径迁移期双读**：值有 `enc:v1:` 前缀则解密、无前缀（明文遗留行）
//!   原样返回；key 名有摘要化前历史的行（遗留 raw key）读取/消费时回退可达
//!   （见 [`FieldEncryptionDao::get`] 文档）
//! - **AAD 绑定** `garrison:{tenant}:{table}:{key}`（key 段 = 落库 key 余段，
//!   摘要化后即摘要值）：密文挪到其他行解密即失败
//!
//! # 命名空间与敏感列对应（规格选定列）
//!
//! - `oauth2:atoken:` / `oauth2:rtoken:`：OAuth2 access/refresh token 记录
//!   （`src/oauth2_server/token.rs` 签发与 DAO fallback 路径；key 余段 = token）
//! - `oauth2:codeused:`：授权码已签发 token 的吊销追踪记录
//!   （`src/oauth2_server/authorize.rs`；key 余段 = 授权码，值含原始 token）
//! - `totp:seed:`：TOTP 种子（预留——当前代码库种子仅内存持有，无落库写入点；
//!   接入持久化时自动纳入加密；key 余段 = 用户标识，非凭据，不摘要化）
//!
//! # 偏差说明：`oauth2:client:` 不纳入
//!
//! 规格 IdP client secret 落库列在本代码库不存在：`DaoOAuth2ClientStore`
//! 持久的 `client_secret_hash` 是 Argon2id 单向哈希（`oauth2_server/client.rs`，
//! 不可逆、非可复用凭据），整值加密无机密性增益；且该 store 的 update 路径是
//! `compare_and_swap`，随机 nonce 加密下 expected（读回的明文）与底层密文
//! 逐字节恒不等，CAS 原理性不可用。恢复 secret 必须先引入 secret 恢复语义
//! （如版本键乐观并发或字段级加密），届时单独接线。
//!
//! # 原子操作限制
//!
//! 计数/比较类原子操作（`incr` / `decr` / `compare_and_swap` /
//! `compare_and_update_if_greater`）依赖明文数值语义，敏感命名空间内无意义且
//! 无法在保持原子性的前提下加解密——显性拒绝（fail-closed），非敏感命名空间透传。
//!
//! # `keys()` 语义
//!
//! `keys(pattern)` 透传内部 DAO：摘要化命名空间返回的是落库 key（摘要形式），
//! **不可回喂 `get()`**（摘要单向，二次摘要错位）。扫描仅供运维工具
//! （change-key / check-key 经内部 DAO 直接操作落库 key）使用。

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};

use super::cipher::FieldCipher;
use super::crypto_value::AadBinding;

/// 敏感命名空间（含末尾冒号；`table` 段为 AAD 第二绑定维度）。
pub const SENSITIVE_TABLES: &[&str] = &[
    "oauth2:atoken:",
    "oauth2:rtoken:",
    "oauth2:codeused:",
    "totp:seed:",
];

/// key 名摘要化命名空间：key 余段是 bearer 凭据（token / 授权码），
/// 落库前摘要为 SHA-256 hex。均为 [`SENSITIVE_TABLES`] 子集。
pub const DIGEST_TABLES: &[&str] = &["oauth2:atoken:", "oauth2:rtoken:", "oauth2:codeused:"];

/// 摘要化后 key 余段的形态：SHA-256 hex 小写（64 字符十六进制）。
///
/// 用于区分「落库 key（已摘要）」与「升级前遗留 raw key」。现实凭据格式
/// （base64url 43 字符，见 `oauth2_server::token::generate_token`）与 64 hex
/// 无交集；误判方向良性——遗留行被当作已摘要时原地保留，读路径回退仍可达。
pub fn is_digest_form(remainder: &str) -> bool {
    remainder.len() == 64
        && remainder
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// 透明加解密 DAO 装饰器。
pub struct FieldEncryptionDao {
    inner: Arc<dyn GarrisonDao>,
    /// 当前字段加解密门面（ArcSwap：change-key 成功后原位切换）。
    cipher: ArcSwap<FieldCipher>,
    /// AAD 租户段（单租户部署用 "default"；多租户按租户装配独立装饰器实例）。
    tenant: String,
}

impl std::fmt::Debug for FieldEncryptionDao {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 内部 dao / cipher 为 trait 对象（无 Debug 约束），只输出装配元信息
        f.debug_struct("FieldEncryptionDao")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl FieldEncryptionDao {
    /// 装配：包装内部 DAO 与字段加解密门面。
    ///
    /// `inner` 必须是未经本装饰器包装的底层存储 DAO（运维接口经
    /// `Self::inner_dao` 直接操作落库层，不存在「误传装饰器实例」的入参位；
    /// inner_dao 为 pub(crate)，不渲染进公开文档，故此处不作 intra-doc 链接）。
    pub fn new(
        inner: Arc<dyn GarrisonDao>,
        cipher: Arc<FieldCipher>,
        tenant: &str,
    ) -> GarrisonResult<Self> {
        if tenant.is_empty() {
            return Err(GarrisonError::Config(
                "secure-field-encryption-dao::empty-tenant".to_string(),
            ));
        }
        Ok(Self {
            inner,
            cipher: ArcSwap::from(cipher),
            tenant: tenant.to_string(),
        })
    }

    /// 内部底层存储 DAO（落库 key 直达，运维 change-key / check-key 专用）。
    pub(crate) fn inner_dao(&self) -> &dyn GarrisonDao {
        self.inner.as_ref()
    }

    /// 当前字段加解密门面快照。
    pub(crate) fn current_cipher(&self) -> Arc<FieldCipher> {
        self.cipher.load().clone()
    }

    /// 原位切换字段加解密门面（change-key 成功后调用；后续写入走新主钥）。
    pub(crate) fn swap_cipher(&self, new_cipher: FieldCipher) {
        self.cipher.store(Arc::new(new_cipher));
    }

    /// key 是否命中敏感命名空间（运维 change-key / check-key 扫描过滤共用）。
    pub(crate) fn is_sensitive(key: &str) -> bool {
        SENSITIVE_TABLES.iter().any(|t| key.starts_with(t))
    }

    /// 调用方 key → 落库 key：摘要化命名空间将余段替换为 SHA-256 hex，
    /// 其余命名空间原样。
    pub(crate) fn storage_key(key: &str) -> String {
        for table in DIGEST_TABLES {
            if let Some(remainder) = key.strip_prefix(table) {
                let digest = Sha256::digest(remainder.as_bytes());
                let mut hex = String::with_capacity(64);
                for byte in digest {
                    hex.push_str(&format!("{byte:02x}"));
                }
                return format!("{table}{hex}");
            }
        }
        key.to_string()
    }

    /// key（落库形态）→ AAD 绑定：table = 命名空间段（去尾冒号），
    /// key = 落库 key 余段（摘要化命名空间即摘要值）。
    pub(crate) fn aad_for_key(&self, stored_key: &str) -> AadBinding {
        for table in SENSITIVE_TABLES {
            if let Some(row) = stored_key.strip_prefix(table) {
                return AadBinding::new(&self.tenant, &table[..table.len() - 1], row);
            }
        }
        AadBinding::new(&self.tenant, "unknown", stored_key)
    }

    /// 写路径加密：非敏感命名空间原样；敏感命名空间按落库 key 的 AAD 全加密。
    async fn encrypt_for_write(&self, stored_key: &str, value: &str) -> GarrisonResult<String> {
        if !Self::is_sensitive(stored_key) {
            return Ok(value.to_string());
        }
        self.current_cipher()
            .encrypt(&self.aad_for_key(stored_key), value)
    }

    /// 读路径双读：有 `enc:v1:` 前缀解密；明文遗留行原样。
    async fn decrypt_for_read(
        &self,
        stored_key: &str,
        value: Option<String>,
    ) -> GarrisonResult<Option<String>> {
        let Some(value) = value else {
            return Ok(None);
        };
        if !Self::is_sensitive(stored_key) {
            return Ok(Some(value));
        }
        self.current_cipher()
            .decrypt(&self.aad_for_key(stored_key), &value)
            .map(Some)
    }

    /// 敏感命名空间读取：摘要化 key 未命中时回退遗留 raw key 行
    /// （升级前以裸 token key 名落库的行，TTL 内仍可读/可消费）。
    async fn sensitive_get(&self, presented: &str) -> GarrisonResult<Option<String>> {
        let stored = Self::storage_key(presented);
        if stored != presented {
            if let Some(raw) = self.inner.get(&stored).await? {
                return self.decrypt_for_read(&stored, Some(raw)).await;
            }
        }
        let raw = self.inner.get(presented).await?;
        self.decrypt_for_read(presented, raw).await
    }

    fn unsupported_op(key: &str, op: &str) -> GarrisonError {
        GarrisonError::Internal(format!(
            "secure-field-encryption-dao::{op}-unsupported-on-sensitive-namespace::key-prefix={}",
            key.split(':').take(2).collect::<Vec<_>>().join(":")
        ))
    }
}

#[async_trait]
impl GarrisonDao for FieldEncryptionDao {
    /// 摘要化命名空间先查落库 key（摘要形式），未命中回退遗留 raw key 行。
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        if !Self::is_sensitive(key) {
            return self.inner.get(key).await;
        }
        self.sensitive_get(key).await
    }

    /// 写入恒落库到摘要化 key（遗留 raw key 行不经写路径复活，按 TTL 消亡
    /// 或由 change-key 收敛）。
    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
        let stored = Self::storage_key(key);
        let encrypted = self.encrypt_for_write(&stored, value).await?;
        self.inner.set(&stored, &encrypted, ttl_seconds).await
    }

    /// 更新恒作用于摘要化 key（遗留 raw key 行不迁移——update 须保留原 TTL，
    /// 跨 key 搬迁做不到，交由 change-key 收敛）。
    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let stored = Self::storage_key(key);
        let encrypted = self.encrypt_for_write(&stored, value).await?;
        self.inner.update(&stored, &encrypted).await
    }

    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
        self.inner.expire(&Self::storage_key(key), seconds).await
    }

    /// 双删：摘要化 key + 遗留 raw key（后者 best-effort，清残留）。
    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        let stored = Self::storage_key(key);
        self.inner.delete(&stored).await?;
        if stored != key && Self::is_sensitive(key) {
            // 遗留 raw key 行清理失败不阻断（TTL 兜底），但删除主键失败已上抛
            let _ = self.inner.delete(key).await;
        }
        Ok(())
    }

    async fn set_permanent(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let stored = Self::storage_key(key);
        let encrypted = self.encrypt_for_write(&stored, value).await?;
        self.inner.set_permanent(&stored, &encrypted).await
    }

    /// SETNX 恒作用于摘要化 key（跨双 key 的原子 absent 判定不可得，
    /// 遗留 raw key 行不计入存在性——仅影响升级窗口内同 token 重签发的
    /// 去重语义，token 签发路径不依赖 SETNX，无实际调用方）。
    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        let stored = Self::storage_key(key);
        let encrypted = self.encrypt_for_write(&stored, value).await?;
        self.inner
            .set_if_absent(&stored, &encrypted, ttl_seconds)
            .await
    }

    async fn get_timeout(&self, key: &str) -> GarrisonResult<Option<std::time::Duration>> {
        self.inner.get_timeout(&Self::storage_key(key)).await
    }

    /// 读值段双读解密后返回（TTL 段透传）；摘要化命名空间带遗留 raw key 回退。
    async fn get_with_ttl(
        &self,
        key: &str,
    ) -> GarrisonResult<Option<(String, Option<std::time::Duration>)>> {
        let stored = Self::storage_key(key);
        let (found_key, value_ttl) = if stored != key && Self::is_sensitive(key) {
            match self.inner.get_with_ttl(&stored).await? {
                Some(pair) => (stored, Some(pair)),
                None => match self.inner.get_with_ttl(key).await? {
                    Some(pair) => (key.to_string(), Some(pair)),
                    None => (key.to_string(), None),
                },
            }
        } else {
            match self.inner.get_with_ttl(&stored).await? {
                Some(pair) => (stored, Some(pair)),
                None => (stored, None),
            }
        };
        match value_ttl {
            None => Ok(None),
            Some((value, ttl)) => self
                .decrypt_for_read(&found_key, Some(value))
                .await
                .map(|v| v.map(|v| (v, ttl))),
        }
    }

    async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
        self.inner.keys(pattern).await
    }

    /// 重命名：值随 key 迁移后 AAD 不再匹配，敏感命名空间先解密、
    /// 原子重命名、再按新落库 key 重加密回写（非原子的崩溃窗口：
    /// 窗口内留下绑定旧 key 的密文，读路径显性报错而非静默错值；
    /// 重加密失败则回滚重命名）。
    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()> {
        if !Self::is_sensitive(old_key) && !Self::is_sensitive(new_key) {
            return self.inner.rename(old_key, new_key).await;
        }
        let old_stored = Self::storage_key(old_key);
        let new_stored = Self::storage_key(new_key);
        let plaintext = self.get(old_key).await?.ok_or_else(|| {
            GarrisonError::InvalidParam(format!(
                "secure-field-encryption-dao::rename-missing-key::{old_key}"
            ))
        })?;
        self.inner.rename(&old_stored, &new_stored).await?;
        match self.encrypt_for_write(&new_stored, &plaintext).await {
            Ok(encrypted) => self.inner.update(&new_stored, &encrypted).await,
            Err(e) => {
                self.inner.rename(&new_stored, &old_stored).await?;
                Err(e)
            },
        }
    }

    /// 原子取删：摘要化命名空间带遗留 raw key 回退，读段双读解密。
    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
        if !Self::is_sensitive(key) {
            let raw = self.inner.get_and_delete(key).await?;
            return self.decrypt_for_read(key, raw).await;
        }
        let stored = Self::storage_key(key);
        let hit_digest = if stored != key {
            self.inner
                .get_and_delete(&stored)
                .await?
                .map(|raw| (stored.clone(), Some(raw)))
        } else {
            None
        };
        let (found_key, raw) = match hit_digest {
            Some(pair) => pair,
            None => (key.to_string(), self.inner.get_and_delete(key).await?),
        };
        // 遗留 raw key 行已随取删；摘要化命中时清理 raw 残留（best-effort）
        if found_key == stored && stored != key {
            let _ = self.inner.delete(key).await;
        }
        self.decrypt_for_read(&found_key, raw).await
    }

    async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64> {
        if Self::is_sensitive(key) {
            return Err(Self::unsupported_op(key, "incr"));
        }
        self.inner.incr(key, ttl_seconds).await
    }

    async fn decr(&self, key: &str) -> GarrisonResult<u64> {
        if Self::is_sensitive(key) {
            return Err(Self::unsupported_op(key, "decr"));
        }
        self.inner.decr(key).await
    }

    async fn compare_and_update_if_greater(
        &self,
        key: &str,
        new_value: u64,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        if Self::is_sensitive(key) {
            return Err(Self::unsupported_op(key, "compare_and_update_if_greater"));
        }
        self.inner
            .compare_and_update_if_greater(key, new_value, ttl_seconds)
            .await
    }

    /// CAS 在敏感命名空间显性拒绝：expected 是读回的解密明文，底层落的是
    /// 本次随机 nonce 的密文，逐字节比较恒不等——CAS 与随机 nonce 加密
    /// 原理性不兼容（依赖 CAS 更新的 store 需改造为版本键乐观并发或
    /// 字段级加密后再接入，见模块文档 `oauth2:client:` 偏差说明）。
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        if Self::is_sensitive(key) {
            return Err(Self::unsupported_op(key, "compare_and_swap"));
        }
        self.inner
            .compare_and_swap(key, expected, new_value, ttl_seconds)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::InMemoryDao;
    use crate::secure::encryption::cipher::StaticFieldKeyProvider;
    use crate::secure::encryption::crypto_value::KEY_LEN;

    const K1: [u8; KEY_LEN] = [1u8; KEY_LEN];

    fn fixture() -> (FieldEncryptionDao, Arc<dyn GarrisonDao>) {
        let inner: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let provider = Arc::new(StaticFieldKeyProvider::new(vec![("k1".to_string(), K1)]).unwrap());
        let cipher = Arc::new(FieldCipher::new(provider).unwrap());
        let dao = FieldEncryptionDao::new(inner.clone(), cipher, "tenant-1").unwrap();
        (dao, inner)
    }

    /// 新写入均为密文 + key 名摘要化：裸 token 不得出现在落库 key 名或值中；
    /// 非敏感命名空间字节级透传。
    #[tokio::test]
    async fn write_path_encrypts_value_and_digests_key() {
        let (dao, inner) = fixture();
        dao.set("oauth2:atoken:bearer-secret-token", "secret-token", 60)
            .await
            .unwrap();
        dao.set("session:s-1", "raw-session", 60).await.unwrap();

        let stored_keys = inner.keys("oauth2:atoken:*").await.unwrap();
        assert_eq!(stored_keys.len(), 1);
        let stored_key = &stored_keys[0];
        assert_ne!(
            stored_key.as_str(),
            "oauth2:atoken:bearer-secret-token",
            "落库 key 不得为裸 token"
        );
        assert!(!stored_key.contains("bearer-secret-token"));
        assert_eq!(stored_key.len(), "oauth2:atoken:".len() + 64);
        assert!(is_digest_form(&stored_key["oauth2:atoken:".len()..]));

        let raw_value = inner.get(stored_key).await.unwrap().unwrap();
        assert!(
            raw_value.starts_with("enc:v1:"),
            "敏感列必须密文落库: {raw_value}"
        );
        assert_ne!(raw_value, "secret-token");

        let raw_session = inner.get("session:s-1").await.unwrap().unwrap();
        assert_eq!(raw_session, "raw-session", "非敏感命名空间透传");
    }

    /// 摘要化 key 名下按原 key（裸 token）读回明文——调用方透传语义不变；
    /// 同一 token 派生的落库 key 确定性一致。
    #[tokio::test]
    async fn digest_key_lookup_transparent() {
        let (dao, inner) = fixture();
        dao.set("oauth2:rtoken:refresh-abc", "refresh-record", 60)
            .await
            .unwrap();
        assert_eq!(
            dao.get("oauth2:rtoken:refresh-abc").await.unwrap().unwrap(),
            "refresh-record"
        );

        let keys = inner.keys("oauth2:rtoken:*").await.unwrap();
        assert_eq!(keys.len(), 1, "同一 token 只落一行");
        dao.set("oauth2:rtoken:refresh-abc", "updated", 60)
            .await
            .unwrap();
        let keys_after = inner.keys("oauth2:rtoken:*").await.unwrap();
        assert_eq!(keys_after, keys, "重复写同 token 落同 key（摘要确定性）");
        assert_eq!(
            dao.get("oauth2:rtoken:refresh-abc").await.unwrap().unwrap(),
            "updated"
        );
    }

    /// roundtrip：经装饰器写入后读回明文（set / update / set_permanent /
    /// set_if_absent 四条写路径全覆盖）。
    #[tokio::test]
    async fn read_roundtrip_across_write_paths() {
        let (dao, inner) = fixture();

        dao.set("oauth2:atoken:a", "v-set", 60).await.unwrap();
        assert_eq!(dao.get("oauth2:atoken:a").await.unwrap().unwrap(), "v-set");

        dao.update("oauth2:atoken:a", "v-update").await.unwrap();
        assert_eq!(
            dao.get("oauth2:atoken:a").await.unwrap().unwrap(),
            "v-update"
        );

        dao.set_permanent("totp:seed:uid", "v-permanent")
            .await
            .unwrap();
        assert_eq!(
            dao.get("totp:seed:uid").await.unwrap().unwrap(),
            "v-permanent"
        );

        let inserted = dao
            .set_if_absent("oauth2:rtoken:r", "v-setnx", 60)
            .await
            .unwrap();
        assert!(inserted);
        assert_eq!(
            dao.get("oauth2:rtoken:r").await.unwrap().unwrap(),
            "v-setnx"
        );

        // set_if_absent 二次调用不写入（SETNX 语义经加密保持）
        let second = dao
            .set_if_absent("oauth2:rtoken:r", "v-other", 60)
            .await
            .unwrap();
        assert!(!second);

        // 四条写路径底层均为密文
        for prefix in ["oauth2:atoken:", "totp:seed:", "oauth2:rtoken:"] {
            let stored = inner.keys(&format!("{prefix}*")).await.unwrap();
            assert_eq!(stored.len(), 1, "{prefix}");
            let raw = inner.get(&stored[0]).await.unwrap().unwrap();
            assert!(raw.starts_with("enc:v1:"), "{prefix} 必须密文落库: {raw}");
        }
    }

    /// 迁移期双读（值维度）：明文遗留行经装饰器读原样返回。
    #[tokio::test]
    async fn legacy_plaintext_row_readable() {
        let (dao, inner) = fixture();
        // 非摘要化命名空间：原 key 直写
        inner
            .set("totp:seed:legacy", "plain-legacy", 0)
            .await
            .unwrap();
        assert_eq!(
            dao.get("totp:seed:legacy").await.unwrap().unwrap(),
            "plain-legacy"
        );
    }

    /// 迁移期双读（key 维度）：升级前以裸 token key 名落库的遗留行，
    /// 按原 key 读取/消费仍可达（读路径回退）。
    #[tokio::test]
    async fn legacy_raw_key_row_readable_and_consumable() {
        let (dao, inner) = fixture();
        // 升级前形态：裸 token key 名 + 明文值
        inner
            .set("oauth2:atoken:legacy-raw-token", "plain-legacy-row", 60)
            .await
            .unwrap();
        assert_eq!(
            dao.get("oauth2:atoken:legacy-raw-token")
                .await
                .unwrap()
                .unwrap(),
            "plain-legacy-row"
        );

        // get_and_delete 消费遗留行（refresh 消费路径）
        let consumed = dao
            .get_and_delete("oauth2:atoken:legacy-raw-token")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(consumed, "plain-legacy-row");
        assert!(dao
            .get("oauth2:atoken:legacy-raw-token")
            .await
            .unwrap()
            .is_none());
    }

    /// 密文挪到他行（AAD 不匹配）解密显性失败，不返回错值。
    #[tokio::test]
    async fn ciphertext_moved_to_other_row_fails() {
        let (dao, inner) = fixture();
        dao.set("totp:seed:row-a", "secret", 60).await.unwrap();
        let stored_keys = inner.keys("totp:seed:*").await.unwrap();
        let raw = inner.get(&stored_keys[0]).await.unwrap().unwrap();

        // 把 row-a 的密文手工落到 row-b 的落库 key（模拟 DB 泄露后的行挪用）
        inner.set("totp:seed:row-b", &raw, 60).await.unwrap();
        let err = dao.get("totp:seed:row-b").await.unwrap_err();
        assert!(
            matches!(err, GarrisonError::Internal(_)),
            "挪用行必须显性报错: {err:?}"
        );
    }

    /// get_and_delete / get_with_ttl 读段双读解密。
    #[tokio::test]
    async fn atomic_read_paths_dual_read() {
        let (dao, _inner) = fixture();
        dao.set("totp:seed:user-1", "seed-secret", 60)
            .await
            .unwrap();

        let (value, ttl) = dao.get_with_ttl("totp:seed:user-1").await.unwrap().unwrap();
        assert_eq!(value, "seed-secret");
        assert!(ttl.is_some());

        let deleted = dao
            .get_and_delete("totp:seed:user-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(deleted, "seed-secret");
        assert!(dao.get("totp:seed:user-1").await.unwrap().is_none());
    }

    /// rename：敏感命名空间重命名后新落库 key 下仍可解（按新 key AAD 重加密），
    /// 旧 key 不存在。
    #[tokio::test]
    async fn rename_reencrypts_under_new_key() {
        let (dao, inner) = fixture();
        dao.set("totp:seed:old-id", "seed-config", 0).await.unwrap();

        dao.rename("totp:seed:old-id", "totp:seed:new-id")
            .await
            .unwrap();
        assert!(inner.get("totp:seed:old-id").await.unwrap().is_none());

        let stored = inner.keys("totp:seed:new-id*").await.unwrap();
        assert_eq!(stored.len(), 1);
        let raw = inner.get(&stored[0]).await.unwrap().unwrap();
        assert!(raw.starts_with("enc:v1:"));
        assert_eq!(
            dao.get("totp:seed:new-id").await.unwrap().unwrap(),
            "seed-config"
        );
    }

    /// 计数/CAS 原子操作在敏感命名空间显性拒绝（明文数值语义与加密不兼容，
    /// fail-closed）；非敏感命名空间（含 `oauth2:client:`）正常透传。
    #[tokio::test]
    async fn counter_ops_rejected_on_sensitive_namespace() {
        let (dao, _inner) = fixture();

        let err = dao.incr("totp:seed:counter", 60).await.unwrap_err();
        assert!(matches!(err, GarrisonError::Internal(_)), "got: {err:?}");
        let err = dao.decr("oauth2:atoken:c").await.unwrap_err();
        assert!(matches!(err, GarrisonError::Internal(_)));
        let err = dao
            .compare_and_swap("oauth2:rtoken:c", None, "x", 60)
            .await
            .unwrap_err();
        assert!(matches!(err, GarrisonError::Internal(_)));

        // 非敏感命名空间透传正常（oauth2:client: 已移出敏感命名空间，
        // DaoOAuth2ClientStore 的 CAS 更新路径不受影响）
        assert_eq!(dao.incr("session:counter", 60).await.unwrap(), 1);
        let swapped = dao
            .compare_and_swap("oauth2:client:cid", None, r#"{"v":1}"#, 60)
            .await
            .unwrap();
        assert!(swapped);
    }

    /// 空租户名装配显性拒绝（AAD 租户段不可为空）。
    #[test]
    fn empty_tenant_rejected() {
        let inner: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let provider = Arc::new(StaticFieldKeyProvider::new(vec![("k1".to_string(), K1)]).unwrap());
        let cipher = Arc::new(FieldCipher::new(provider).unwrap());
        let err = FieldEncryptionDao::new(inner, cipher, "").unwrap_err();
        assert!(matches!(err, GarrisonError::Config(_)), "got: {err:?}");
    }
}
