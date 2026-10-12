// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! DaoCredentialRepository 实现块。
//!
//! IDOR 防护：`find_by_user` / `update` / `delete` 先校验 `caller_login_id` 与目标凭证 `user_id`
//! 一致，否则返回 `GarrisonError::NotPermission`（HTTP 403），拒绝事件经 `tracing::warn!` 记录。
//!
//! 并发语义（已知限制）：`update` 用 `compare_and_swap`（expected = 读取值）写入，并发修改显式返回
//! `credential-concurrent-modification` 错误而非静默覆盖；`delete` 两阶段（先全量校验 ownership 再删除）
//! 消除部分删除，但校验与删除间仍有理论窗口（DAO trait 无 compare-and-delete 原语，需强一致请在 DAO
//! 层实现）；`keys()` 错误原样上抛（不静默），`GarrisonDaoOxcache` 未启用 `dao-key-index` 时不支持（见 mod.rs）。

use super::*;
use crate::dao::repository::validate_imported_hash;

impl DaoCredentialRepository {
    /// 创建 `DaoCredentialRepository`（`dao` 为已初始化的 `GarrisonDao` 实现）。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self { dao }
    }

    /// 生成 DAO key：`cred:{user_id}:{cred_id}`。
    fn make_key(user_id: &str, cred_id: &str) -> String {
        format!("{}{}:{}", DaoKeyPrefix::Cred, user_id, cred_id)
    }

    /// 反序列化凭证 JSON；DAO 中残留非法 JSON 时返回 `GarrisonError::Internal`。
    fn deserialize_credential(json: &str) -> GarrisonResult<CredentialModel> {
        serde_json::from_str(json)
            .map_err(|e| GarrisonError::Internal(format!("account-cred-deserialize::{}", e)))
    }

    /// 序列化凭证 JSON；序列化失败返回 `GarrisonError::Internal`。
    fn serialize_credential(credential: &CredentialModel) -> GarrisonResult<String> {
        serde_json::to_string(credential)
            .map_err(|e| GarrisonError::Internal(format!("account-cred-serialize::{}", e)))
    }
}

#[async_trait]
impl CredentialRepository for DaoCredentialRepository {
    async fn create(&self, credential: CredentialModel) -> GarrisonResult<()> {
        // 导入哈希防御门：仅约束 password 类型（TOTP seed / backup code 等非 PHC 载荷不受约束）
        if credential.credential_type == "password" {
            validate_imported_hash(&credential.secret_data).map_err(|e| {
                GarrisonError::InvalidParam(format!("credential-create-hash-gate::{}", e))
            })?;
        }
        let key = Self::make_key(&credential.user_id, &credential.id);
        let json = Self::serialize_credential(&credential)?;
        // 使用 set_if_absent 原子操作替代 get-then-set，消除 TOCTOU 竞态
        let inserted = self.dao.set_if_absent(&key, &json, 0).await?;
        if !inserted {
            return Err(GarrisonError::InvalidParam(format!(
                "credential-already-exists::{}",
                credential.id
            )));
        }
        Ok(())
    }

    async fn find_by_user(
        &self,
        caller_login_id: &str,
        user_id: &str,
    ) -> GarrisonResult<Vec<CredentialModel>> {
        // IDOR 防护：caller 必须是自己
        if caller_login_id != user_id {
            tracing::warn!(
                caller_login_id = caller_login_id,
                target_user_id = user_id,
                "credential find_by_user denied: caller != target (IDOR)"
            );
            return Err(GarrisonError::NotPermission(format!(
                "credential-query-forbidden::{}::{}",
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
    ) -> GarrisonResult<Vec<CredentialModel>> {
        // 安全语义：受信接口（调用方应在认证上下文中使用，user_id 即为会话主体），
        // 内部以 find_by_user(user_id, user_id) 调用并执行 IDOR 校验
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
    ) -> GarrisonResult<()> {
        // IDOR 防护：经 credential_id（UUID 全局唯一）扫描定位既有凭证，而非用新 model 的 user_id
        // 构造 key（否则攻击者改 user_id 会查不到，无法触发拒绝路径）
        let pattern = format!("{}*:{}", DaoKeyPrefix::Cred, credential.id);
        let keys = self.dao.keys(&pattern).await?;
        // credential_id 全局唯一，正常情况下 keys 仅 1 个；为空表示凭证不存在
        let existing_key = match keys.into_iter().next() {
            Some(k) => k,
            None => {
                return Err(GarrisonError::InvalidParam(format!(
                    "credential-not-found::{}",
                    credential.id
                )));
            },
        };
        let existing_json = match self.dao.get(&existing_key).await? {
            Some(json) => json,
            None => {
                return Err(GarrisonError::InvalidParam(format!(
                    "credential-not-found::{}",
                    credential.id
                )));
            },
        };
        let existing: CredentialModel = Self::deserialize_credential(&existing_json)?;

        // IDOR 防护 1：caller 必须是凭证原 owner
        if existing.user_id != caller_login_id {
            tracing::warn!(
                caller_login_id = caller_login_id,
                owner_user_id = %existing.user_id,
                credential_id = %credential.id,
                "credential update denied: caller != owner (IDOR)"
            );
            return Err(GarrisonError::NotPermission(format!(
                "credential-update-forbidden::{}::{} (owner {})",
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
            return Err(GarrisonError::NotPermission(format!(
                "credential-transfer-forbidden::{}::{} -> {}",
                credential.id, existing.user_id, credential.user_id
            )));
        }

        // user_id 不可变 ⇒ existing_key 与新 key 一致，复用 existing_key 写回。
        // 导入哈希防御门在 IDOR 检查全部通过后执行：未授权调用方统一得到 NotPermission，
        // 不泄露校验细节；仅 password 类型过门。
        if credential.credential_type == "password" {
            validate_imported_hash(&credential.secret_data).map_err(|e| {
                GarrisonError::InvalidParam(format!("credential-update-hash-gate::{}", e))
            })?;
        }
        let json = Self::serialize_credential(&credential)?;
        // 用 CAS（expected = 读取时的值）替代 set_permanent 直写，消除 keys→get→set TOCTOU 竞态下的
        // 静默覆盖：并发修改/删除时 CAS 失败显式报错（CAS 重试会覆盖他人更新，不适用）
        let swapped = self
            .dao
            .compare_and_swap(&existing_key, Some(&existing_json), &json, 0)
            .await?;
        if !swapped {
            tracing::warn!(
                caller_login_id = caller_login_id,
                credential_id = %credential.id,
                "credential update aborted: concurrent modification detected (CAS mismatch)"
            );
            return Err(GarrisonError::Internal(format!(
                "credential-concurrent-modification::{}",
                credential.id
            )));
        }
        Ok(())
    }

    async fn delete(&self, caller_login_id: &str, credential_id: &str) -> GarrisonResult<()> {
        // credential_id 全局唯一（UUID v4），扫描 cred:*:{credential_id} 定位完整 key
        let pattern = format!("{}*:{}", DaoKeyPrefix::Cred, credential_id);
        let keys = self.dao.keys(&pattern).await?;
        if keys.is_empty() {
            return Err(GarrisonError::InvalidParam(format!(
                "credential-not-found::{}",
                credential_id
            )));
        }

        // 两阶段删除：先校验全部命中 key 的 ownership 再删除，避免异常多键场景下「先删本人 key、
        // 后遇他人 key 返回 NotPermission」的部分删除无回滚问题；校验与删除之间仍有窗口
        // （DAO trait 无 compare-and-delete 原语），残余 TOCTOU 见模块文档。
        let mut verified_keys = Vec::with_capacity(keys.len());
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
                return Err(GarrisonError::NotPermission(format!(
                    "credential-delete-forbidden::{}::{} (owner {})",
                    caller_login_id, credential_id, existing.user_id
                )));
            }
            verified_keys.push(key);
        }

        // 阶段 2：全部校验通过后删除（任一删除失败即中断并向上传播错误）
        for key in verified_keys {
            self.dao.delete(&key).await?;
        }
        Ok(())
    }
}
