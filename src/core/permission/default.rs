//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `PermissionCheckerDefault` 实现块（从 mod.rs 迁移）。

use super::*;

impl PermissionCheckerDefault {
    /// 创建新的 `PermissionCheckerDefault` 实例。
    pub fn new(interface: Arc<dyn BulwarkInterface>) -> Self {
        Self { interface }
    }
}

#[async_trait]
impl PermissionChecker for PermissionCheckerDefault {
    async fn has_permission(&self, login_id: &str, permission: &str) -> BulwarkResult<bool> {
        // P2.4: NFC 规范化 permission 字符串，防止 Unicode 同形异义字攻击
        // （NFD 与 NFC 形式视觉相同但字节不同，规范化后统一比较）
        let normalized = permission.nfc().collect::<String>();
        if normalized.is_empty() {
            return Err(BulwarkError::InvalidParam("权限字符串不能为空".to_string()));
        }
        // P2.4: 长度校验（>256 字节返回 InvalidParam），防止 DoS
        if normalized.len() > 256 {
            return Err(BulwarkError::InvalidParam(format!(
                "permission too long: {} bytes (max 256)",
                normalized.len()
            )));
        }
        let perms = self.interface.get_permission_list(login_id).await?;
        Ok(perms.iter().any(|p| p == &normalized))
    }

    async fn has_role(&self, login_id: &str, role: &str) -> BulwarkResult<bool> {
        if role.is_empty() {
            return Err(BulwarkError::InvalidParam("角色字符串不能为空".to_string()));
        }
        let roles = self.interface.get_role_list(login_id).await?;
        Ok(roles.iter().any(|r| r == role))
    }

    // check_permission / check_role 使用 trait 默认实现（委托 authorize / has_role），
    // 保持与 0.5.0 决策溯源路径一致。

    async fn has_any_permission(&self, login_id: &str, perms: &[&str]) -> bool {
        for perm in perms {
            if self.has_permission(login_id, perm).await.unwrap_or(false) {
                return true;
            }
        }
        false
    }

    async fn has_all_permissions(&self, login_id: &str, perms: &[&str]) -> bool {
        for perm in perms {
            if !self.has_permission(login_id, perm).await.unwrap_or(false) {
                return false;
            }
        }
        true
    }
}
