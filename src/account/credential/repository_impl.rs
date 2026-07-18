//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DaoCredentialRepository 实现块（从 mod.rs 迁移）。

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
        let json = serde_json::to_string(&credential)
            .map_err(|e| BulwarkError::Internal(format!("account-cred-serialize::{}", e)))?;
        self.dao.set_permanent(&key, &json).await
    }

    async fn find_by_user(&self, user_id: &str) -> BulwarkResult<Vec<CredentialModel>> {
        let pattern = format!("{}{}:*", DaoKeyPrefix::Cred, user_id);
        let keys = self.dao.keys(&pattern).await?;
        let mut result = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(json) = self.dao.get(&key).await? {
                let model: CredentialModel = serde_json::from_str(&json).map_err(|e| {
                    BulwarkError::Internal(format!("account-cred-deserialize::{}", e))
                })?;
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
        let all = self.find_by_user(user_id).await?;
        Ok(all
            .into_iter()
            .filter(|c| c.credential_type == cred_type)
            .collect())
    }

    async fn update(&self, credential: CredentialModel) -> BulwarkResult<()> {
        let key = Self::make_key(&credential.user_id, &credential.id);
        // 检查存在性（trait 契约：不存在返回 InvalidParam）
        if self.dao.get(&key).await?.is_none() {
            return Err(BulwarkError::InvalidParam(format!(
                "credential not found: {}",
                credential.id
            )));
        }
        let json = serde_json::to_string(&credential)
            .map_err(|e| BulwarkError::Internal(format!("account-cred-serialize::{}", e)))?;
        self.dao.set_permanent(&key, &json).await
    }

    async fn delete(&self, credential_id: &str) -> BulwarkResult<()> {
        // credential_id 全局唯一（UUID v4），扫描 cred:*:{credential_id} 定位完整 key
        let pattern = format!("{}*:{}", DaoKeyPrefix::Cred, credential_id);
        let keys = self.dao.keys(&pattern).await?;
        if keys.is_empty() {
            return Err(BulwarkError::InvalidParam(format!(
                "credential not found: {}",
                credential_id
            )));
        }
        for key in keys {
            self.dao.delete(&key).await?;
        }
        Ok(())
    }
}
