//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! MockInterface 的 `GarrisonInterface` trait 实现。
//!
//! 从 `mod.rs` 迁移而出（规则 25：mod.rs 接口隔离）。
//! 提供 E2E 测试用的空权限/空角色 mock 实现。

use async_trait::async_trait;
use garrison::error::GarrisonResult;
use garrison::stp::GarrisonInterface;

use super::MockInterface;

#[async_trait]
impl GarrisonInterface for MockInterface {
    async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
}
