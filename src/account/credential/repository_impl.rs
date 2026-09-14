//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! DaoCredentialRepository 实现块（从 mod.rs 迁移）。
//!
//! # IDOR 防护（vuln-0004 修复）
//!
//! `find_by_user` / `update` / `delete` 在执行前先校验 `caller_login_id` 与目标
//! 凭证的 `user_id` 一致，否则返回 `GarrisonError::NotPermission`（HTTP 403）。
//! 拒绝事件通过 `tracing::warn!` 记录，便于安全审计订阅。
//!
//! # 并发语义（已知限制）
//!
//! - `update` 使用 `compare_and_swap`（expected = 读取值）写入，并发修改会显式
//!   返回 `credential-concurrent-modification` 错误，不静默覆盖（Issue 2743）。
//! - `delete` 采用两阶段（先全量校验 ownership 再删除，Issue 6852），消除混合
//!   IDOR 结果下的部分删除；但校验与删除之间仍存在理论窗口——`GarrisonDao`
//!   trait 暂无 compare-and-delete 原语，需要强一致删除时请在 DAO 后端层实现。
//! - `keys()` 的错误原样向上传播（不静默吞掉）；`GarrisonDaoOxcache` 默认
//!   （未启用 `dao-key-index`）不支持 `keys()`，见 mod.rs「已知限制」。

use super::*;

impl DaoCredentialRepository {
    /// 创建 `DaoCredentialRepository`。
    ///
    /// # 参数
    /// - `dao`: 已初始化的 `GarrisonDao` 实现（`Arc<dyn GarrisonDao>`）。
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
        let key = Self::make_key(&credential.user_id, &credential.id);
        let json = Self::serialize_credential(&credential)?;
        // Issue 10: 使用 set_if_absent 原子操作替代 get-then-set，消除 TOCTOU 竞态
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
        // IDOR 防护：caller 必须是自己（vuln-0004）
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
    ) -> GarrisonResult<()> {
        // IDOR 防护：通过 credential_id（UUID 全局唯一）扫描定位既有凭证，
        // 而非用新 model 的 user_id 直接构造 key（否则攻击者改 user_id 会查不到，无法触发拒绝路径）。
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

        // IDOR 防护 1：caller 必须是凭证原 owner（vuln-0004）
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

        // user_id 不可变 ⇒ existing_key 与新 key 一致，复用 existing_key 写回
        let json = Self::serialize_credential(&credential)?;
        // Issue 2743: 用 CAS（expected = 读取时的值）替代 set_permanent 直写，
        // 消除 keys→get→set TOCTOU 竞态下的静默覆盖：并发修改/删除本凭证时
        // CAS 失败，显式报错而非覆盖他方写入（CAS 重试会覆盖他人更新，不适用）。
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

        // Issue 6852: 两阶段删除——先校验全部命中 key 的 ownership，全部通过后才
        // 进入删除阶段。避免异常多键场景下「先删了本人的 key、后遇他人 key 返回
        // NotPermission」的部分删除无回滚问题。
        // 注意：校验与删除之间仍存在窗口（DAO trait 无 compare-and-delete 原语），
        // 该残余 TOCTOU 见模块文档「已知限制」。
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
