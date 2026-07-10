//! 备份码凭证子模块。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 提供 `BackupCodeCredential`，实现 `Credential` trait，支持生成 10 个一次性
//! MFA 备份码（8 字节随机数 → Base32 → `XXXX-XXXX-XXXX` 格式）。
//!
//! ## secret_data 格式
//!
//! `CredentialModel.secret_data` 存储如下 JSON：
//!
//! ```json
//! {"codes":["hash1","hash2",...]}
//! ```
//!
//! - `codes`: SHA-256 哈希列表（每个备份码的规范化形式哈希后存入）
//!
//! 备份码明文仅在 `generate()` 返回时可见，此后仅以哈希形式存储。
//! `verify_and_consume()` 校验通过后从列表中移除该哈希（一次性使用）。

use super::{Credential, CredentialModel, CredentialType};
use crate::constants::DaoKeyPrefix;
use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 备份码数量。
const CODE_COUNT: usize = 10;

/// 每个备份码的随机字节数。
const CODE_BYTES: usize = 8;

/// 备份码 secret_data 的 JSON 结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupCodeSecretData {
    /// SHA-256 哈希列表（每个备份码的规范化形式哈希后存入）。
    codes: Vec<String>,
}

impl BackupCodeSecretData {
    /// 从 `secret_data` JSON 字符串解析。
    fn from_json(secret_data: &str) -> BulwarkResult<Self> {
        serde_json::from_str(secret_data).map_err(|e| {
            BulwarkError::InvalidParam(format!(
                "backup_code secret_data 解析失败（期望 JSON {{codes: [...]}}）: {}",
                e
            ))
        })
    }
}

/// 将输入字符串计算 SHA-256 并返回小写十六进制字符串。
fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

/// 规范化备份码输入：移除 `-` 分隔符并转为大写。
fn normalize(input: &str) -> String {
    input.to_uppercase().replace('-', "")
}

/// 将 Base32 编码字符串格式化为 `XXXX-XXXX-XXXX`（取前 12 字符，每 4 字符一组）。
fn format_code(base32_str: &str) -> String {
    format!(
        "{}-{}-{}",
        &base32_str[..4],
        &base32_str[4..8],
        &base32_str[8..12]
    )
}

/// 备份码凭证（实现 [`Credential`] trait，支持一次性 MFA 备份码）。
///
/// 持有 `CredentialModel`，`secret_data` 存储备份码的 SHA-256 哈希列表。
/// `generate()` 生成 10 个一次性备份码，明文仅此一次返回。
/// `verify_and_consume()` 校验输入并消费（一次性使用），更新 DAO。
///
/// # 示例
///
/// ```ignore
/// use bulwark::account::credential::backup_code::BackupCodeCredential;
///
/// let (cred, codes) = BackupCodeCredential::generate("alice")?;
/// // 将 cred.to_model() 持久化到 DAO 后，可用 verify_and_consume 校验
/// ```
#[cfg_attr(
    feature = "account-credential-zeroize",
    derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)
)]
pub struct BackupCodeCredential {
    /// 凭证存储模型。
    model: CredentialModel,
}

impl BackupCodeCredential {
    /// 创建备份码凭证。
    ///
    /// # 参数
    /// - `model`: 凭证存储模型（`secret_data` 应为 `{"codes":["hash1",...]}` JSON）
    pub fn new(model: CredentialModel) -> Self {
        Self { model }
    }

    /// 生成 10 个一次性备份码。
    ///
    /// 每个备份码：8 字节随机数（`OsRng`）→ Base32 编码 → 格式化为 `XXXX-XXXX-XXXX`。
    /// 备份码的 SHA-256 哈希存入 `secret_data`，明文仅此一次返回。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（用户 ID），存入 `CredentialModel.user_id`。
    ///
    /// # 返回
    /// - `Ok((credential, codes))`: 凭证 + 10 个明文备份码列表。
    /// - `Err(_)`: 序列化失败。
    pub fn generate(login_id: &str) -> BulwarkResult<(BackupCodeCredential, Vec<String>)> {
        let mut codes = Vec::with_capacity(CODE_COUNT);
        let mut hashes = Vec::with_capacity(CODE_COUNT);
        for _ in 0..CODE_COUNT {
            let mut bytes = [0u8; CODE_BYTES];
            OsRng.fill_bytes(&mut bytes);
            let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes);
            let formatted = format_code(&encoded);
            let normalized = normalize(&formatted);
            codes.push(formatted);
            hashes.push(sha256_hex(&normalized));
        }
        let secret_data =
            serde_json::to_string(&BackupCodeSecretData { codes: hashes }).map_err(|e| {
                BulwarkError::Internal(format!("backup_code secret_data 序列化失败: {}", e))
            })?;
        let model = CredentialModel {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: login_id.to_string(),
            credential_type: "backup_code".to_string(),
            secret_data,
            label: None,
            created_at: chrono::Utc::now().timestamp(),
            enabled: true,
            priority: 0,
        };
        Ok((BackupCodeCredential { model }, codes))
    }

    /// 校验并消费备份码（一次性使用）。
    ///
    /// 从 DAO 读取当前 `CredentialModel`，将输入（规范化后）的 SHA-256 哈希
    /// 与 `secret_data` 中的哈希列表比对。匹配则从列表中移除该哈希并更新 DAO；
    /// 不匹配返回 `Ok(false)`。
    ///
    /// # 参数
    /// - `input`: 用户输入的备份码（可能含 `-` 分隔符，自动规范化）。
    /// - `dao`: DAO 抽象（用于读取/更新 `CredentialModel`）。
    ///
    /// # 返回
    /// - `Ok(true)`: 校验通过且备份码已消费。
    /// - `Ok(false)`: 校验失败（备份码不匹配或已使用）。
    /// - `Err(_)`: `secret_data` 解析失败或 DAO 读写失败。
    pub async fn verify_and_consume(
        &self,
        input: &str,
        dao: &dyn BulwarkDao,
    ) -> BulwarkResult<bool> {
        let key = format!(
            "{}{}:{}",
            DaoKeyPrefix::Cred,
            self.model.user_id,
            self.model.id
        );
        let json = match dao.get(&key).await? {
            Some(j) => j,
            None => {
                return Err(BulwarkError::InvalidParam(format!(
                    "backup_code credential not found in DAO: {}",
                    key
                )))
            },
        };
        let model: CredentialModel = serde_json::from_str(&json)
            .map_err(|e| BulwarkError::Internal(format!("CredentialModel 反序列化失败: {}", e)))?;
        let mut data = BackupCodeSecretData::from_json(&model.secret_data)?;
        let input_hash = sha256_hex(&normalize(input));
        if let Some(idx) = data.codes.iter().position(|h| *h == input_hash) {
            data.codes.remove(idx);
            let new_secret = serde_json::to_string(&data).map_err(|e| {
                BulwarkError::Internal(format!("backup_code secret_data 序列化失败: {}", e))
            })?;
            let mut updated_model = model.clone();
            updated_model.secret_data = new_secret;
            let updated_json = serde_json::to_string(&updated_model).map_err(|e| {
                BulwarkError::Internal(format!("CredentialModel 序列化失败: {}", e))
            })?;
            dao.set_permanent(&key, &updated_json).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[async_trait]
impl Credential for BackupCodeCredential {
    fn credential_type(&self) -> CredentialType {
        "backup_code"
    }

    fn to_model(&self) -> CredentialModel {
        self.model.clone()
    }

    async fn verify(&self, input: &str) -> BulwarkResult<bool> {
        let data = BackupCodeSecretData::from_json(&self.model.secret_data)?;
        let input_hash = sha256_hex(&normalize(input));
        Ok(data.codes.contains(&input_hash))
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    /// 辅助函数：将 BackupCodeCredential 的 model 持久化到 DAO。
    async fn store_in_dao(cred: &BackupCodeCredential, dao: &MockDao) {
        let model = cred.to_model();
        let key = format!("cred:{}:{}", model.user_id, model.id);
        let json = serde_json::to_string(&model).expect("序列化应成功");
        dao.set_permanent(&key, &json)
            .await
            .expect("DAO 写入应成功");
    }

    /// `generate()` 返回 10 个备份码。
    #[test]
    fn generate_returns_10_codes() {
        let (cred, codes) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        assert_eq!(codes.len(), 10, "应生成 10 个备份码");
        assert_eq!(
            cred.credential_type(),
            "backup_code",
            "credential_type 应为 backup_code"
        );
    }

    /// `generate()` 每个备份码格式为 `XXXX-XXXX-XXXX`（14 字符：12 字母数字 + 2 连字符）。
    #[test]
    fn generate_codes_have_correct_format() {
        let (_, codes) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        for code in &codes {
            assert_eq!(
                code.len(),
                14,
                "备份码应为 14 字符（XXXX-XXXX-XXXX），实际: {}",
                code
            );
            let parts: Vec<&str> = code.split('-').collect();
            assert_eq!(parts.len(), 3, "备份码应有 3 段，实际: {}", code);
            for part in &parts {
                assert_eq!(part.len(), 4, "每段应为 4 字符，实际: {}", part);
                assert!(
                    part.chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
                    "每段应为 Base32 字符（A-Z, 2-7），实际: {}",
                    part
                );
            }
        }
    }

    /// `generate()` 返回的 10 个备份码互不重复。
    #[test]
    fn generate_codes_are_unique() {
        let (_, codes) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), 10, "10 个备份码应互不重复");
    }

    /// `credential_type()` 返回 `"backup_code"`。
    #[test]
    fn credential_type_returns_backup_code() {
        let (cred, _) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        assert_eq!(cred.credential_type(), "backup_code");
    }

    /// `to_model()` 返回原始 CredentialModel（字段一致）。
    #[test]
    fn to_model_returns_original() {
        let (cred, _) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        let model = cred.to_model();
        assert_eq!(model.user_id, "alice");
        assert_eq!(model.credential_type, "backup_code");
        assert!(model.secret_data.contains("codes"));
        assert!(model.enabled);
    }

    /// `verify_and_consume()` 正确备份码返回 `Ok(true)`。
    #[tokio::test]
    async fn verify_and_consume_correct_code() {
        let (cred, codes) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        let dao = MockDao::new();
        store_in_dao(&cred, &dao).await;

        let result = cred
            .verify_and_consume(&codes[0], &dao)
            .await
            .expect("verify_and_consume 应成功");
        assert!(result, "正确备份码应校验通过");
    }

    /// `verify_and_consume()` 已使用的备份码返回 `Ok(false)`（一次性使用）。
    #[tokio::test]
    async fn verify_and_consume_rejects_used_code() {
        let (cred, codes) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        let dao = MockDao::new();
        store_in_dao(&cred, &dao).await;

        let first = cred
            .verify_and_consume(&codes[0], &dao)
            .await
            .expect("首次校验应成功");
        assert!(first, "首次应通过");

        let second = cred
            .verify_and_consume(&codes[0], &dao)
            .await
            .expect("二次校验应成功");
        assert!(!second, "已使用的备份码应被拒绝（一次性使用）");
    }

    /// `verify_and_consume()` 错误备份码返回 `Ok(false)`。
    #[tokio::test]
    async fn verify_and_consume_wrong_code_returns_false() {
        let (cred, _) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        let dao = MockDao::new();
        store_in_dao(&cred, &dao).await;

        let result = cred
            .verify_and_consume("WRONG-CODE-XXXX", &dao)
            .await
            .expect("verify_and_consume 应成功");
        assert!(!result, "错误备份码应返回 false");
    }

    /// `verify_and_consume()` 支持含 `-` 和不含 `-` 两种输入形式。
    #[tokio::test]
    async fn verify_and_consume_normalizes_input() {
        let (cred, codes) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        let dao = MockDao::new();
        store_in_dao(&cred, &dao).await;

        let normalized = codes[0].replace('-', "");
        let result = cred
            .verify_and_consume(&normalized, &dao)
            .await
            .expect("verify_and_consume 应成功");
        assert!(result, "不含连字符的输入应校验通过");
    }

    /// `verify_and_consume()` 小写输入应通过（规范化转大写）。
    #[tokio::test]
    async fn verify_and_consume_lowercase_input() {
        let (cred, codes) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        let dao = MockDao::new();
        store_in_dao(&cred, &dao).await;

        let lower = codes[0].to_lowercase();
        let result = cred
            .verify_and_consume(&lower, &dao)
            .await
            .expect("verify_and_consume 应成功");
        assert!(result, "小写输入应校验通过（规范化转大写）");
    }

    /// `Credential::verify()` 正确备份码返回 `Ok(true)`（仅比对，不消费）。
    #[tokio::test]
    async fn verify_correct_code() {
        let (cred, codes) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        let result = cred.verify(&codes[0]).await.expect("verify 应成功");
        assert!(result, "正确备份码应校验通过");
    }

    /// `Credential::verify()` 错误备份码返回 `Ok(false)`。
    #[tokio::test]
    async fn verify_wrong_code() {
        let (cred, _) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        let result = cred.verify("WRONG-CODE-XXXX").await.expect("verify 应成功");
        assert!(!result, "错误备份码应返回 false");
    }

    /// `Credential::verify()` 不消费备份码（verify 后 verify_and_consume 仍应通过）。
    #[tokio::test]
    async fn verify_does_not_consume() {
        let (cred, codes) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        let dao = MockDao::new();
        store_in_dao(&cred, &dao).await;

        let verify_result = cred.verify(&codes[0]).await.expect("verify 应成功");
        assert!(verify_result, "verify 应通过");

        let consume_result = cred
            .verify_and_consume(&codes[0], &dao)
            .await
            .expect("verify_and_consume 应成功");
        assert!(consume_result, "verify 不应消费备份码");
    }

    /// `BackupCodeCredential` 可作 `Box<dyn Credential>` 使用（对象安全验证）。
    #[tokio::test]
    async fn usable_as_dyn_credential() {
        let (cred, codes) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        let dyn_cred: Box<dyn Credential> = Box::new(cred);
        assert_eq!(dyn_cred.credential_type(), "backup_code");
        let result = dyn_cred.verify(&codes[0]).await.expect("verify 应成功");
        assert!(result, "dyn Credential 正确备份码应校验通过");
    }

    /// `secret_data` JSON 解析 — 非法 JSON 返回错误。
    #[tokio::test]
    async fn invalid_secret_data_returns_error() {
        let model = CredentialModel {
            id: "bad".to_string(),
            user_id: "alice".to_string(),
            credential_type: "backup_code".to_string(),
            secret_data: "not-json".to_string(),
            label: None,
            created_at: 0,
            enabled: true,
            priority: 0,
        };
        let cred = BackupCodeCredential::new(model);
        let result = cred.verify("XXXX-XXXX-XXXX").await;
        assert!(result.is_err(), "非法 secret_data 应返回错误");
    }

    /// 消费全部 10 个备份码后，第 11 次校验返回 `Ok(false)`。
    #[tokio::test]
    async fn consume_all_codes_then_reject() {
        let (cred, codes) = BackupCodeCredential::generate("alice").expect("generate 应成功");
        let dao = MockDao::new();
        store_in_dao(&cred, &dao).await;

        for code in &codes {
            let result = cred
                .verify_and_consume(code, &dao)
                .await
                .expect("verify_and_consume 应成功");
            assert!(result, "每个备份码首次使用应通过: {}", code);
        }

        let result = cred
            .verify_and_consume(&codes[0], &dao)
            .await
            .expect("verify_and_consume 应成功");
        assert!(!result, "全部消费后应返回 false");
    }
}
