// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 密钥轮换运维接口：change-key（全量重加密）与 check-key（可解密性校验）。
//!
//! 二者实现为 [`FieldEncryptionDao`] 方法（而非自由函数接 `&dyn GarrisonDao`）：
//! 操作对象恒为装饰器持有的**底层存储 DAO**（落库 key 直达），误把装饰器
//! 实例当存储传入导致的「解密后再加密」双重加密在类型上不可表达。
//! 面向运维 CLI（garrison-cli）暴露——garrison-cli 子命令接线依赖
//! R16（段 10）合入基线后补齐，本模块即其接口层。
//!
//! - change-key：敏感命名空间全部行重加密到新 [`FieldCipher`] 主钥；
//!   明文遗留行补加密；遗留 raw key 行（升级前裸 token key 名）迁移到
//!   摘要化 key 名并删除原行；已新主钥的行跳过（幂等）。报告 `failed`
//!   非空时**不切换**当前门面（保持旧钥可读失败行），调用方据报告处置；
//!   全部成功才切换，此后写入走新主钥。
//! - check-key：按当前门面逐行校验，产出结构化健康报告（可解密 / 明文遗留 /
//!   遗留 raw key / 损坏行逐 key 列出，不静默）。
//!
//! 批处理：`batch_size` 切分扫描结果以限制单批内存占用；行级失败记录进报告
//! 后继续，单坏行不阻塞全量轮换。多实例部署应停写或加互斥后执行
//! （`GarrisonDao` 抽象不提供跨行事务，单行 `update` / `set` 原子）。

use crate::error::{GarrisonError, GarrisonResult};

use super::crypto_value::CryptoValue;
use super::dao::{is_digest_form, FieldEncryptionDao, DIGEST_TABLES};

/// change-key 执行报告。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ChangeKeyReport {
    /// 扫描到的敏感命名空间落库 key 总数（含跳过与失败）。
    pub scanned: usize,
    /// 密文行重加密到新主钥的行数。
    pub reencrypted: usize,
    /// 明文遗留行补加密的行数。
    pub legacy_plaintext_reencrypted: usize,
    /// 遗留 raw key 行迁移到摘要化 key 名并删除原行的行数。
    pub legacy_key_migrated: usize,
    /// 已是新主钥加密而跳过的行数（幂等重跑）。
    pub skipped_current_key: usize,
    /// 失败行（key, 原因）——非空时当前门面不切换，调用方必须处置。
    pub failed: Vec<(String, String)>,
}

impl ChangeKeyReport {
    /// 报告是否完全干净（无失败行）。
    pub fn is_clean(&self) -> bool {
        self.failed.is_empty()
    }
}

/// check-key 执行报告。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CheckKeyReport {
    /// 扫描到的敏感命名空间落库 key 总数。
    pub scanned: usize,
    /// 当前门面可解密的密文行数。
    pub encrypted_ok: usize,
    /// 明文遗留行数（未加密，迁移未完成）。
    pub legacy_plaintext: usize,
    /// 遗留 raw key 行数（升级前 key 名形态，change-key 可迁移收敛）。
    pub legacy_raw_key: usize,
    /// 损坏行（key, 原因）：编码不合法或当前门面不可解——调用方必须检查非空。
    pub corrupt: Vec<(String, String)>,
}

impl FieldEncryptionDao {
    /// 全量重加密到 `new_cipher` 的主钥（change-key）。
    ///
    /// 成功（`failed` 为空）后当前门面切换为 `new_cipher`；否则保持旧门面，
    /// 失败行明细见报告。幂等：重跑收敛。
    pub async fn change_key(
        &self,
        new_cipher: super::cipher::FieldCipher,
        batch_size: usize,
    ) -> GarrisonResult<ChangeKeyReport> {
        if batch_size == 0 {
            return Err(GarrisonError::InvalidParam(
                "secure-field-encryption-change-key::batch-size-zero".to_string(),
            ));
        }
        let old_cipher = self.current_cipher();
        let new_primary = new_cipher.primary_key_id()?;
        let keys = self.filtered_sensitive_keys("*").await?;
        let mut report = ChangeKeyReport {
            scanned: keys.len(),
            ..Default::default()
        };

        for batch in keys.chunks(batch_size) {
            for stored_key in batch {
                let Some(raw) = self.inner_dao().get(stored_key).await? else {
                    continue;
                };
                match self
                    .reencrypt_row(&old_cipher, &new_cipher, &new_primary, stored_key, &raw)
                    .await
                {
                    Ok(Some(RowOutcome::Reencrypted)) => report.reencrypted += 1,
                    Ok(Some(RowOutcome::LegacyPlaintext)) => {
                        report.legacy_plaintext_reencrypted += 1
                    },
                    Ok(Some(RowOutcome::LegacyKeyMigrated)) => report.legacy_key_migrated += 1,
                    Ok(None) => report.skipped_current_key += 1,
                    Err(reason) => report.failed.push((stored_key.clone(), reason)),
                }
            }
        }

        if report.is_clean() {
            self.swap_cipher(new_cipher);
        }
        Ok(report)
    }

    /// 可解密性校验（check-key）：按当前门面逐行检查敏感命名空间，
    /// `pattern` 限定扫描范围（如 `oauth2:atoken:*`）。
    pub async fn check_key(&self, pattern: &str) -> GarrisonResult<CheckKeyReport> {
        let cipher = self.current_cipher();
        let keys = self.filtered_sensitive_keys(pattern).await?;
        let mut report = CheckKeyReport {
            scanned: keys.len(),
            ..Default::default()
        };

        for stored_key in keys {
            let Some(raw) = self.inner_dao().get(&stored_key).await? else {
                continue;
            };
            if is_legacy_raw_key(&stored_key) {
                report.legacy_raw_key += 1;
            }
            if !raw.starts_with(CryptoValue::PREFIX) {
                report.legacy_plaintext += 1;
                continue;
            }
            match cipher.decrypt(&self.aad_for_key(&stored_key), &raw) {
                Ok(_) => report.encrypted_ok += 1,
                Err(e) => report.corrupt.push((stored_key, e.to_string())),
            }
        }
        Ok(report)
    }

    /// 敏感命名空间内的落库 key（按 pattern 扫描后过滤，排序稳定）。
    async fn filtered_sensitive_keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
        let all = self.inner_dao().keys(pattern).await?;
        let mut keys: Vec<String> = all.into_iter().filter(|k| Self::is_sensitive(k)).collect();
        keys.sort();
        Ok(keys)
    }

    /// 单行重加密。返回 `Ok(None)` = 已新主钥且 key 形态最新（跳过）；
    /// `Ok(Some(outcome))` = 处理完成；`Err(reason)` = 行级失败（进报告）。
    ///
    /// 遗留 raw key 行（摘要化命名空间内非 64-hex 余段）重加密后写入摘要化
    /// key 并删除原行（TTL 经 get_with_ttl 保留；后端不支持 TTL 查询时该行
    /// 记为失败——显性化，不静默丢 TTL）。
    async fn reencrypt_row(
        &self,
        old_cipher: &super::cipher::FieldCipher,
        new_cipher: &super::cipher::FieldCipher,
        new_primary: &str,
        stored_key: &str,
        raw: &str,
    ) -> Result<Option<RowOutcome>, String> {
        let was_encrypted = raw.starts_with(CryptoValue::PREFIX);
        let plaintext = if was_encrypted {
            match CryptoValue::decode(raw) {
                Ok(value) if value.key_id == new_primary && !is_legacy_raw_key(stored_key) => {
                    return Ok(None);
                },
                // 旧值按其所在行（源 key）的 AAD 解密
                Ok(_) => old_cipher
                    .decrypt(&self.aad_for_key(stored_key), raw)
                    .map_err(|e| e.to_string())?,
                Err(e) => return Err(e.to_string()),
            }
        } else {
            raw.to_string()
        };
        // 遗留 raw key 行迁移后落在摘要化 key：新值 AAD 绑定目标 key
        // （与读路径一致——按落库 key 的 AAD 解密）
        let legacy_key = is_legacy_raw_key(stored_key);
        let aad_key = if legacy_key {
            Self::storage_key(stored_key)
        } else {
            stored_key.to_string()
        };
        let stored = new_cipher
            .encrypt(&self.aad_for_key(&aad_key), &plaintext)
            .map_err(|e| e.to_string())?;

        if legacy_key {
            // 遗留 raw key → 摘要化 key 迁移（TTL 保留；TTL 查询失败显性记为失败）
            let target = aad_key;
            let ttl = match self
                .inner_dao()
                .get_with_ttl(stored_key)
                .await
                .map_err(|e| e.to_string())?
            {
                Some((_, Some(d))) => d.as_secs().max(1),
                Some((_, None)) => 0,
                // get_with_ttl 内部 get 刚命中过，None 只可能来自 TTL 查询失败
                None => return Err("legacy-key-migration::ttl-query-unsupported".to_string()),
            };
            self.inner_dao()
                .set(&target, &stored, ttl)
                .await
                .map_err(|e| e.to_string())?;
            self.inner_dao()
                .delete(stored_key)
                .await
                .map_err(|e| e.to_string())?;
            return Ok(Some(RowOutcome::LegacyKeyMigrated));
        }

        self.inner_dao()
            .update(stored_key, &stored)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Some(if was_encrypted {
            RowOutcome::Reencrypted
        } else {
            RowOutcome::LegacyPlaintext
        }))
    }
}

/// 行处理结果分类（报告计数用）。
enum RowOutcome {
    /// 密文行重加密。
    Reencrypted,
    /// 明文遗留行补加密。
    LegacyPlaintext,
    /// 遗留 raw key 行迁移到摘要化 key 名。
    LegacyKeyMigrated,
}

/// 落库 key 是否为遗留 raw key 形态（摘要化命名空间内非摘要余段）。
fn is_legacy_raw_key(stored_key: &str) -> bool {
    for table in DIGEST_TABLES {
        if let Some(remainder) = stored_key.strip_prefix(table) {
            return !is_digest_form(remainder);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::dao::{GarrisonDao, InMemoryDao};
    use crate::secure::encryption::cipher::{FieldCipher, StaticFieldKeyProvider};
    use crate::secure::encryption::crypto_value::KEY_LEN;

    const K1: [u8; KEY_LEN] = [1u8; KEY_LEN];
    const K2: [u8; KEY_LEN] = [2u8; KEY_LEN];

    fn cipher(primary: &str) -> FieldCipher {
        let provider =
            StaticFieldKeyProvider::new(vec![("k1".to_string(), K1), ("k2".to_string(), K2)])
                .unwrap()
                .with_primary(primary)
                .unwrap();
        FieldCipher::new(Arc::new(provider)).unwrap()
    }

    async fn seeded_dao() -> FieldEncryptionDao {
        let inner: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let dao = FieldEncryptionDao::new(inner, Arc::new(cipher("k1")), "tenant-1").unwrap();
        dao.set("oauth2:atoken:tok-1", "token-1", 0).await.unwrap();
        dao.set("oauth2:rtoken:rt-1", "refresh-1", 0).await.unwrap();
        dao.set("totp:seed:uid", "seed-1", 0).await.unwrap();
        dao.set("session:s-1", "not-sensitive", 0).await.unwrap();
        dao
    }

    /// SHA-256 hex 余段（64 位小写十六进制）——测试定位具体 token 的落库 key。
    fn digest_of(remainder: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(remainder.as_bytes());
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// change-key 后全部行可被新钥解密、旧 key_id 行清零；非敏感行不动；
    /// 成功后新写入走新主钥（门面已切换）。
    #[tokio::test]
    async fn change_key_reencrypts_all_rows_to_new_primary() {
        let dao = seeded_dao().await;
        let new = cipher("k2");

        let report = dao.change_key(new.clone(), 2).await.unwrap();
        assert_eq!(report.scanned, 3, "atoken + rtoken + totp:seed");
        assert_eq!(report.reencrypted, 3);
        assert!(report.is_clean(), "失败行: {:?}", report.failed);

        // 全部行可被新钥解密
        let check = dao.check_key("*").await.unwrap();
        assert_eq!(check.encrypted_ok, 3);
        assert_eq!(check.legacy_plaintext, 0);
        assert!(check.corrupt.is_empty(), "损坏行: {:?}", check.corrupt);

        // 旧 key_id 行清零：落库值均以 enc:v1:k2: 开头
        for prefix in ["oauth2:atoken:", "oauth2:rtoken:", "totp:seed:"] {
            let keys = dao.inner_dao().keys(&format!("{prefix}*")).await.unwrap();
            assert_eq!(keys.len(), 1, "{prefix}");
            let raw = dao.inner_dao().get(&keys[0]).await.unwrap().unwrap();
            assert!(raw.starts_with("enc:v1:k2:"), "{prefix}: {raw}");
        }

        // 非敏感行字节级不动
        assert_eq!(
            dao.inner_dao().get("session:s-1").await.unwrap().unwrap(),
            "not-sensitive"
        );

        // 门面已切换：新写入走新主钥
        dao.set("oauth2:atoken:tok-new", "token-new", 0)
            .await
            .unwrap();
        let raw = dao
            .inner_dao()
            .get(&format!("oauth2:atoken:{}", digest_of("tok-new")))
            .await
            .unwrap()
            .unwrap();
        assert!(
            raw.starts_with("enc:v1:k2:"),
            "切换后新写入必须用新主钥: {raw}"
        );
    }

    /// 摘要化命名空间遗留 raw key 行：change-key 迁移到摘要化 key 名并删除
    /// 原行，TTL 保留；按原 token 读取仍可达。
    #[tokio::test]
    async fn change_key_migrates_legacy_raw_keys() {
        let inner: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let dao =
            FieldEncryptionDao::new(inner.clone(), Arc::new(cipher("k1")), "tenant-1").unwrap();
        // 升级前形态：裸 token key 名 + 明文值
        dao.inner_dao()
            .set("oauth2:atoken:legacy-raw-token", "plain-row", 3600)
            .await
            .unwrap();

        let report = dao.change_key(cipher("k2"), 10).await.unwrap();
        assert_eq!(report.legacy_key_migrated, 1, "报告: {:?}", report);
        assert!(report.is_clean());
        assert!(
            dao.inner_dao()
                .get("oauth2:atoken:legacy-raw-token")
                .await
                .unwrap()
                .is_none(),
            "遗留 raw key 行必须删除"
        );

        // 摘要化 key 下可解、legacy_raw_key 清零、TTL 保留
        let check = dao.check_key("oauth2:atoken:*").await.unwrap();
        assert_eq!(check.encrypted_ok, 1);
        assert_eq!(check.legacy_raw_key, 0);
        let (_, ttl) = dao
            .get_with_ttl("oauth2:atoken:legacy-raw-token")
            .await
            .unwrap()
            .unwrap();
        assert!(ttl.is_some(), "迁移必须保留 TTL");
        assert_eq!(
            dao.get("oauth2:atoken:legacy-raw-token")
                .await
                .unwrap()
                .unwrap(),
            "plain-row"
        );
    }

    /// change-key 幂等：重跑全部跳过（含已迁移行），结果不变。
    #[tokio::test]
    async fn change_key_is_idempotent() {
        let dao = seeded_dao().await;
        dao.change_key(cipher("k2"), 10).await.unwrap();

        let rerun = dao.change_key(cipher("k2"), 10).await.unwrap();
        assert_eq!(rerun.scanned, 3);
        assert_eq!(rerun.reencrypted, 0);
        assert_eq!(rerun.skipped_current_key, 3);
        assert!(rerun.is_clean());
    }

    /// check-key 对损坏行显性报告（不静默、不中断其余行分类）。
    #[tokio::test]
    async fn check_key_reports_corrupt_rows() {
        let dao = seeded_dao().await;
        // 损坏行：enc: 前缀 + 非法载荷；遗留明文行
        dao.inner_dao()
            .set("totp:seed:corrupt", "enc:v1:k1:AAAA", 0)
            .await
            .unwrap();
        dao.inner_dao()
            .set("totp:seed:legacy-plain", "plain-row", 0)
            .await
            .unwrap();

        let report = dao.check_key("*").await.unwrap();
        assert_eq!(report.scanned, 5);
        assert_eq!(report.encrypted_ok, 3);
        assert_eq!(report.legacy_plaintext, 1);
        assert_eq!(report.corrupt.len(), 1);
        assert_eq!(report.corrupt[0].0, "totp:seed:corrupt");
    }

    /// change-key 行级失败：门面不切换（保持旧钥可读），报告显性列出。
    #[tokio::test]
    async fn change_key_failure_keeps_old_cipher() {
        let dao = seeded_dao().await;
        // 损坏行：key_id k9 未注册 → 旧门面不可解 → 重加密失败
        dao.inner_dao()
            .set(
                "totp:seed:bad",
                // nosemgrep: generic.secrets.security.detected-telegram-bot-api-key.detected-telegram-bot-api-key —— 刻意构造的损坏密文夹具（k9 未注册，非真实凭证）
                "enc:v1:k9:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                0,
            )
            .await
            .unwrap();

        let report = dao.change_key(cipher("k2"), 10).await.unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, "totp:seed:bad");

        // 门面未切换：新写入仍是旧主钥（k1），已有可解行保持 4 行
        dao.set("totp:seed:after-failure", "still-old-key", 0)
            .await
            .unwrap();
        let check = dao.check_key("*").await.unwrap();
        assert_eq!(
            check.encrypted_ok, 4,
            "失败行 + 新写入仍为旧钥: {:?}",
            check
        );
    }

    /// batch_size=0 显性拒绝。
    #[tokio::test]
    async fn change_key_rejects_zero_batch_size() {
        let dao = seeded_dao().await;
        let err = dao.change_key(cipher("k2"), 0).await.unwrap_err();
        assert!(
            matches!(err, GarrisonError::InvalidParam(_)),
            "got: {err:?}"
        );
    }
}
