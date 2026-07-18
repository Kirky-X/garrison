//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 凭证层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockCredentialRepository`（基于 `std::sync::Mutex<HashMap>` 模拟 `CredentialRepository`），
//! 供 `account::credential::tests` 凭证 CRUD 契约测试复用。
//!
//! # IDOR 防护（vuln-0004 修复）
//!
//! Mock 实现同步加入 `caller_login_id` 校验，与 `DaoCredentialRepository` 行为一致，
//! 便于在 trait 契约测试中验证所有权拒绝路径。

use crate::account::credential::{CredentialModel, CredentialRepository};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

/// Mock `CredentialRepository` 实现（内存 HashMap），用于测试 trait 契约。
#[derive(Default)]
pub struct MockCredentialRepository {
    store: Mutex<HashMap<String, CredentialModel>>,
}

#[async_trait]
impl CredentialRepository for MockCredentialRepository {
    async fn create(&self, credential: CredentialModel) -> BulwarkResult<()> {
        let mut store = self.store.lock().unwrap();
        if store.contains_key(&credential.id) {
            return Err(BulwarkError::InvalidParam(format!(
                "credential already exists: {}",
                credential.id
            )));
        }
        store.insert(credential.id.clone(), credential);
        Ok(())
    }

    async fn find_by_user(
        &self,
        caller_login_id: &str,
        user_id: &str,
    ) -> BulwarkResult<Vec<CredentialModel>> {
        // IDOR 防护：caller 必须是自己（vuln-0004）
        if caller_login_id != user_id {
            return Err(BulwarkError::NotPermission(format!(
                "caller {} cannot query credentials of {}",
                caller_login_id, user_id
            )));
        }
        let store = self.store.lock().unwrap();
        let mut creds: Vec<CredentialModel> = store
            .values()
            .filter(|c| c.user_id == user_id)
            .cloned()
            .collect();
        // 按 priority 升序排序
        creds.sort_by_key(|c| c.priority);
        Ok(creds)
    }

    async fn find_by_user_and_type(
        &self,
        user_id: &str,
        cred_type: &str,
    ) -> BulwarkResult<Vec<CredentialModel>> {
        // 安全语义：调用方应在认证上下文中使用，user_id 即为会话主体。
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
        let mut store = self.store.lock().unwrap();
        let existing = match store.get(&credential.id) {
            Some(m) => m.clone(),
            None => {
                return Err(BulwarkError::InvalidParam(format!(
                    "credential not found: {}",
                    credential.id
                )));
            },
        };

        // IDOR 防护 1：caller 必须是凭证原 owner
        if existing.user_id != caller_login_id {
            return Err(BulwarkError::NotPermission(format!(
                "caller {} cannot update credential {} owned by {}",
                caller_login_id, credential.id, existing.user_id
            )));
        }

        // IDOR 防护 2：禁止通过 update 改变 user_id（防止跨用户转移）
        if credential.user_id != existing.user_id {
            return Err(BulwarkError::NotPermission(format!(
                "cannot transfer credential {} from user {} to {}",
                credential.id, existing.user_id, credential.user_id
            )));
        }

        store.insert(credential.id.clone(), credential);
        Ok(())
    }

    async fn delete(&self, caller_login_id: &str, credential_id: &str) -> BulwarkResult<()> {
        let mut store = self.store.lock().unwrap();
        let existing = match store.get(credential_id) {
            Some(m) => m.clone(),
            None => {
                return Err(BulwarkError::InvalidParam(format!(
                    "credential not found: {}",
                    credential_id
                )));
            },
        };

        // IDOR 防护：caller 必须是凭证 owner
        if existing.user_id != caller_login_id {
            return Err(BulwarkError::NotPermission(format!(
                "caller {} cannot delete credential {} owned by {}",
                caller_login_id, credential_id, existing.user_id
            )));
        }

        store.remove(credential_id);
        Ok(())
    }
}
