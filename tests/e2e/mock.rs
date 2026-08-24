//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! MockInterface 的 `GarrisonInterface` trait 实现。
//!
//! 从 `mod.rs` 迁移而出（规则 25：mod.rs 接口隔离）。
//! 提供 E2E 测试用的空权限/空角色 mock 实现。
//!
//! # NEEDS CLARIFICATION: 无产品 GarrisonInterface 实现
//!
//! 仓库内基于 Dao 的 `GarrisonInterface` 仅存在于 `#[cfg(test)]`，无产品实现
//! （trait 为业务方回调）。按 production-mock-purge 规则"不发明生产代码"，
//! 此共享 mock 定义经文件头标注保留，等待用户裁定（见报告 NEEDS CLARIFICATION #1）。

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
