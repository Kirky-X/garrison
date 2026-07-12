//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 权限校验层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockInterface`（基于 `HashMap` 模拟 `BulwarkInterface`），
//! 供 `core::permission::tests` 权限/角色校验测试复用。

use crate::error::BulwarkResult;
use crate::stp::BulwarkInterface;
use async_trait::async_trait;
use std::collections::HashMap;

/// 测试用 mock BulwarkInterface。
pub struct MockInterface {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
}

impl MockInterface {
    /// 创建空的 mock 实例（无任何权限/角色）。
    pub fn new() -> Self {
        Self {
            permissions: HashMap::new(),
            roles: HashMap::new(),
        }
    }

    /// 链式注入指定 login_id 的权限列表。
    pub fn with_perms(mut self, login_id: &str, perms: Vec<&str>) -> Self {
        self.permissions.insert(
            login_id.to_string(),
            perms.iter().map(|s| s.to_string()).collect(),
        );
        self
    }

    /// 链式注入指定 login_id 的角色列表。
    pub fn with_roles(mut self, login_id: &str, roles: Vec<&str>) -> Self {
        self.roles.insert(
            login_id.to_string(),
            roles.iter().map(|s| s.to_string()).collect(),
        );
        self
    }
}

#[async_trait]
impl BulwarkInterface for MockInterface {
    async fn get_permission_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
    }

    async fn get_role_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.roles.get(login_id).cloned().unwrap_or_default())
    }
}
