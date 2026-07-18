//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DaoCredentialRepository 实现块（从 mod.rs 迁移）。
//!
//! # IDOR 防护（vuln-0004 修复）
//!
//! `find_by_user` / `update` / `delete` 在执行前先校验 `caller_login_id` 与目标
//! 凭证的 `user_id` 一致，否则返回 `BulwarkError::NotPermission`（HTTP 403）。
//! 拒绝事件通过 `tracing::warn!` 记录，便于安全审计订阅。

use super::*;

impl DaoCredentialRepository {
    /// 创建 `DaoCredentialRepository`。
    ///
    /// # 参数
    /// - `dao`: 已初始化的 `BulwarkDao` 实现（`Arc<dyn BulwarkDao>`）。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }

    /// 生成 DAO key：`cred:{user_id}:{cred_id}`。
    fn make_key(user_id: &str, cred_id: &str) -> String {
        format!("{}{}:{}", DaoKeyPrefix::Cred, user_id, cred_id)
    }

    /// 反序列化凭证 JSON；DAO 中残留非法 JSON 时返回 `BulwarkError::Internal`。
    fn deserialize_credential(json: &str) -> BulwarkResult<CredentialModel> {
        serde_json::from_str(json)
            .map_err(|e| BulwarkError::Internal(format!("account-cred-deserialize::{}", e)))
    }

    /// 序列化凭证 JSON；序列化失败返回 `BulwarkError::Internal`。
    fn serialize_credential(credential: &CredentialModel) -> BulwarkResult<String> {
        serde_json::to_string(credential)
            .map_err(|e| BulwarkError::Internal(format!("account-cred-serialize::{}", e)))
    }
}

#[async_trait]
impl CredentialRepository for DaoCredentialRepository {
    async fn create(&self, credential: CredentialModel) -> BulwarkResult<()> {
        let key = Self::make_key(&credential.user_id, &credential.id);
        // 检查重复（trait 契约：已存在返回 InvalidParam）
        if self.dao.get(&key).await?.is_some() {
            return Err(BulwarkError::InvalidParam(format!(
                "credential already exists: {}",
                credential.id
            )));
        }
        let json = Self::serialize_credential(&credential)?;
        self.dao.set_permanent(&key, &json).await
    }

    async fn find_by_user(
        &self,
        caller_login_id: &str,
        user_id: &str,
    ) -> BulwarkResult<Vec<CredentialModel>> {
        // IDOR 防护：caller 必须是自己（vuln-0004）
        if caller_login_id != user_id {
            tracing::warn!(
                caller_login_id = caller_login_id,
                target_user_id = user_id,
                "credential find_by_user denied: caller != target (IDOR)"
            );
            return Err(BulwarkError::NotPermission(format!(
                "caller {} cannot query credentials of {}",
                caller_login_id, user_id
            )));
        }
        let pattern = format!("{}{}:*", DaoKeyPrefix::Cred, user_id);
        let keys = self.dao.keys(&pattern).await?;
        let mut result = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(json) = self.dao.get(&key).await? {
                let model: CredentialModel = Self::deserialize_credential(&json)?;
                result.push(model);
            }
        }
        // 按 priority 升序（trait 契约）
        result.sort_by_key(|c| c.priority);
        Ok(result)
    }

    async fn find_by_user_and_type(
        &self,
        user_id: &str,
        cred_type: &str,
    ) -> BulwarkResult<Vec<CredentialModel>> {
        // 安全语义：调用方应在认证上下文中使用，user_id 即为会话主体。
        // 内部以 find_by_user(user_id, user_id) 调用，由其执行 IDOR 校验。
        let all = self.find_by_user(user_id, user_id).await?;
        Ok(all
            .into_iter()
            .filter(|c| c.credential_type == cred_type)
            .collect())
    }

    async fn update(
        &self,
        caller_login_id: &str,
        credential: CredentialModel,
    ) -> BulwarkResult<()> {
        // IDOR 防护：通过 credential_id（UUID 全局唯一）扫描定位既有凭证，
        // 而非用新 model 的 user_id 直接构造 key（否则攻击者改 user_id 会查不到，无法触发拒绝路径）。
        let pattern = format!("{}*:{}", DaoKeyPrefix::Cred, credential.id);
        let keys = self.dao.keys(&pattern).await?;
        // credential_id 全局唯一，正常情况下 keys 仅 1 个；为空表示凭证不存在
        let existing_key = match keys.into_iter().next() {
            Some(k) => k,
            None => {
                return Err(BulwarkError::InvalidParam(format!(
                    "credential not found: {}",
                    credential.id
                )));
            },
        };
        let existing_json = match self.dao.get(&existing_key).await? {
            Some(json) => json,
            None => {
                return Err(BulwarkError::InvalidParam(format!(
                    "credential not found: {}",
                    credential.id
                )));
            },
        };
        let existing: CredentialModel = Self::deserialize_credential(&existing_json)?;

        // IDOR 防护 1：caller 必须是凭证原 owner（vuln-0004）
        if existing.user_id != caller_login_id {
            tracing::warn!(
                caller_login_id = caller_login_id,
                owner_user_id = %existing.user_id,
                credential_id = %credential.id,
                "credential update denied: caller != owner (IDOR)"
            );
            return Err(BulwarkError::NotPermission(format!(
                "caller {} cannot update credential {} owned by {}",
                caller_login_id, credential.id, existing.user_id
            )));
        }

        // IDOR 防护 2：禁止通过 update 改变 user_id（防止凭证跨用户转移）
        if credential.user_id != existing.user_id {
            tracing::warn!(
                caller_login_id = caller_login_id,
                old_user_id = %existing.user_id,
                new_user_id = %credential.user_id,
                credential_id = %credential.id,
                "credential update denied: user_id transfer forbidden (IDOR)"
            );
            return Err(BulwarkError::NotPermission(format!(
                "cannot transfer credential {} from user {} to {}",
                credential.id, existing.user_id, credential.user_id
            )));
        }

        // user_id 不可变 ⇒ existing_key 与新 key 一致，复用 existing_key 写回
        let json = Self::serialize_credential(&credential)?;
        self.dao.set_permanent(&existing_key, &json).await
    }

    async fn delete(&self, caller_login_id: &str, credential_id: &str) -> BulwarkResult<()> {
        // credential_id 全局唯一（UUID v4），扫描 cred:*:{credential_id} 定位完整 key
        let pattern = format!("{}*:{}", DaoKeyPrefix::Cred, credential_id);
        let keys = self.dao.keys(&pattern).await?;
        if keys.is_empty() {
            return Err(BulwarkError::InvalidParam(format!(
                "credential not found: {}",
                credential_id
            )));
        }

        // IDOR 防护：逐个反序列化校验 owner 后才删除（vuln-0004）
        // credential_id 全局唯一，正常情况下 keys 仅 1 个；保留循环以处理异常多键场景。
        for key in keys {
            let json = match self.dao.get(&key).await? {
                Some(j) => j,
                None => continue,
            };
            let existing: CredentialModel = Self::deserialize_credential(&json)?;
            if existing.user_id != caller_login_id {
                tracing::warn!(
                    caller_login_id = caller_login_id,
                    owner_user_id = %existing.user_id,
                    credential_id = %credential_id,
                    "credential delete denied: caller != owner (IDOR)"
                );
                return Err(BulwarkError::NotPermission(format!(
                    "caller {} cannot delete credential {} owned by {}",
                    caller_login_id, credential_id, existing.user_id
                )));
            }
            self.dao.delete(&key).await?;
        }
        Ok(())
    }
}
