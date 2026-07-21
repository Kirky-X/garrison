//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 管理器层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockInterface`（基于 `HashMap` 模拟权限/角色数据回调），
//! 供 `manager::tests` 初始化与鉴权测试复用。

use crate::error::GarrisonResult;
use crate::stp::GarrisonInterface;
use async_trait::async_trait;
use std::collections::HashMap;

/// 测试用 GarrisonInterface mock，基于 HashMap 存储 login_id → 权限/角色列表。
pub struct MockInterface {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
}

impl MockInterface {
    /// 创建空的 mock 实例（无任何权限/角色数据）。
    pub fn new() -> Self {
        Self {
            permissions: HashMap::new(),
            roles: HashMap::new(),
        }
    }

    /// 链式设置指定 login_id 的权限列表。
    pub fn with_permission(mut self, login_id: &str, perms: &[&str]) -> Self {
        self.permissions.insert(
            login_id.to_string(),
            perms.iter().map(|s| s.to_string()).collect(),
        );
        self
    }

    /// 链式设置指定 login_id 的角色列表。
    pub fn with_role(mut self, login_id: &str, roles: &[&str]) -> Self {
        self.roles.insert(
            login_id.to_string(),
            roles.iter().map(|s| s.to_string()).collect(),
        );
        self
    }
}

#[async_trait]
impl GarrisonInterface for MockInterface {
    async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
    }

    async fn get_role_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(self.roles.get(login_id).cloned().unwrap_or_default())
    }
}
