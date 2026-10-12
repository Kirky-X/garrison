// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `PermissionCheckerDefault` 实现块。

use super::*;

impl PermissionCheckerDefault {
    /// 创建新的 `PermissionCheckerDefault` 实例。
    pub fn new(interface: Arc<dyn GarrisonInterface>) -> Self {
        Self { interface }
    }
}

#[async_trait]
impl PermissionChecker for PermissionCheckerDefault {
    async fn has_permission(&self, login_id: &str, permission: &str) -> GarrisonResult<bool> {
        // NFC 规范化防 Unicode 同形异义字攻击（NFD/NFC 视觉相同但字节不同）。
        let normalized = permission.nfc().collect::<String>();
        if normalized.is_empty() {
            return Err(GarrisonError::InvalidParam("core-perm-empty::".to_string()));
        }
        // 长度校验（>256 字节拒绝），防 DoS。
        if normalized.len() > 256 {
            return Err(GarrisonError::InvalidParam(format!(
                "permission-name-too-long::{}",
                normalized.len()
            )));
        }
        let perms = self.interface.get_permission_list(login_id).await?;
        Ok(perms.iter().any(|p| p == &normalized))
    }

    async fn has_role(&self, login_id: &str, role: &str) -> GarrisonResult<bool> {
        // 与 has_permission 对齐（NFC 规范化 + 长度校验）：不规范化会被 NFD/NFC 视觉同形字符串绕过。
        let normalized = role.nfc().collect::<String>();
        if normalized.is_empty() {
            return Err(GarrisonError::InvalidParam("core-role-empty::".to_string()));
        }
        // 长度校验（>256 字节拒绝），防 DoS。
        if normalized.len() > 256 {
            return Err(GarrisonError::InvalidParam(format!(
                "role-name-too-long::{}",
                normalized.len()
            )));
        }
        let roles = self.interface.get_role_list(login_id).await?;
        Ok(roles.contains(&normalized))
    }

    async fn has_permission_in_tenant(
        &self,
        tenant_id: i64,
        login_id: &str,
        permission: &str,
    ) -> GarrisonResult<bool> {
        // NFC 规范化 + 长度校验与 has_permission 同口径（同形异义字 / DoS 防护）。
        let normalized = permission.nfc().collect::<String>();
        if normalized.is_empty() {
            return Err(GarrisonError::InvalidParam("core-perm-empty::".to_string()));
        }
        if normalized.len() > 256 {
            return Err(GarrisonError::InvalidParam(format!(
                "permission-name-too-long::{}",
                normalized.len()
            )));
        }
        // 租户感知：interface 覆写 get_permission_list_in_tenant 时按租户过滤（跨租户重名
        // login_id 不互染），未覆写时委托全局方法，行为与 has_permission 一致。
        let perms = self
            .interface
            .get_permission_list_in_tenant(tenant_id, login_id)
            .await?;
        Ok(perms.iter().any(|p| p == &normalized))
    }

    // check_permission / check_role 用 trait 默认实现（委托 authorize / has_role），与决策溯源路径一致。

    // 批量校验错误处理：返回 `bool` 是公开 API 契约，接口错误逐条 warn 并按 fail-closed 降级为
    //「不满足」（无法从返回值区分故障与无权限，需区分时用 `authorize()`）。
    async fn has_any_permission(&self, login_id: &str, perms: &[&str]) -> bool {
        for perm in perms {
            match self.has_permission(login_id, perm).await {
                Ok(true) => return true,
                Ok(false) => {},
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        login_id = %login_id,
                        permission = %perm,
                        "has_any_permission: has_permission failed, \
                         degrading to not-held (fail-closed; use authorize() to distinguish \
                         denial from backend failure)"
                    );
                },
            }
        }
        false
    }

    async fn has_all_permissions(&self, login_id: &str, perms: &[&str]) -> bool {
        for perm in perms {
            match self.has_permission(login_id, perm).await {
                Ok(true) => {},
                Ok(false) => return false,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        login_id = %login_id,
                        permission = %perm,
                        "has_all_permissions: has_permission failed, \
                         degrading to not-held (fail-closed; use authorize() to distinguish \
                         denial from backend failure)"
                    );
                    return false;
                },
            }
        }
        true
    }
}
