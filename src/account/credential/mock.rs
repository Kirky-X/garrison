//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 凭证层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockCredentialRepository`（基于 `std::sync::Mutex<HashMap>` 模拟 `CredentialRepository`），
//! 供 `account::credential::tests` 凭证 CRUD 契约测试复用。

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

    async fn find_by_user(&self, user_id: &str) -> BulwarkResult<Vec<CredentialModel>> {
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
        let store = self.store.lock().unwrap();
        let mut creds: Vec<CredentialModel> = store
            .values()
            .filter(|c| c.user_id == user_id && c.credential_type == cred_type)
            .cloned()
            .collect();
        creds.sort_by_key(|c| c.priority);
        Ok(creds)
    }

    async fn update(&self, credential: CredentialModel) -> BulwarkResult<()> {
        let mut store = self.store.lock().unwrap();
        if !store.contains_key(&credential.id) {
            return Err(BulwarkError::InvalidParam(format!(
                "credential not found: {}",
                credential.id
            )));
        }
        store.insert(credential.id.clone(), credential);
        Ok(())
    }

    async fn delete(&self, credential_id: &str) -> BulwarkResult<()> {
        let mut store = self.store.lock().unwrap();
        if !store.contains_key(credential_id) {
            return Err(BulwarkError::InvalidParam(format!(
                "credential not found: {}",
                credential_id
            )));
        }
        store.remove(credential_id);
        Ok(())
    }
}
