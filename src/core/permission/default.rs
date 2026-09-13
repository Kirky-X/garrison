//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `PermissionCheckerDefault` 实现块（从 mod.rs 迁移）。

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
        // P2.4: NFC 规范化 permission 字符串，防止 Unicode 同形异义字攻击
        // （NFD 与 NFC 形式视觉相同但字节不同，规范化后统一比较）
        let normalized = permission.nfc().collect::<String>();
        if normalized.is_empty() {
            return Err(GarrisonError::InvalidParam("core-perm-empty::".to_string()));
        }
        // P2.4: 长度校验（>256 字节返回 InvalidParam），防止 DoS
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
        // issue 3079：与 has_permission 对齐——NFC 规范化 + 长度校验。
        // 原实现直接字节比较且无规范化，NFD/NFC 视觉同形字符串可绕过角色校验。
        let normalized = role.nfc().collect::<String>();
        if normalized.is_empty() {
            return Err(GarrisonError::InvalidParam("core-role-empty::".to_string()));
        }
        // P2.4 对齐：长度校验（>256 字节返回 InvalidParam），防止 DoS
        if normalized.len() > 256 {
            return Err(GarrisonError::InvalidParam(format!(
                "role-name-too-long::{}",
                normalized.len()
            )));
        }
        let roles = self.interface.get_role_list(login_id).await?;
        Ok(roles.contains(&normalized))
    }

    // check_permission / check_role 使用 trait 默认实现（委托 authorize / has_role），
    // 保持与 0.5.0 决策溯源路径一致。

    // issue 2669/3249/3573/8233/8382：批量校验的错误处理。
    // 返回类型保持 `bool`（trait 公开 API，变更会破坏所有实现方/调用方），
    // 但接口错误**不再静默**：逐条 `tracing::warn!`（含 login_id / permission / 错误），
    // 并按 fail-closed 降级为「不满足」。调用方仍无法从返回值区分「无权限」与「故障」
    // ——需要该区分时请使用 `authorize()`（返回 GarrisonResult<Decision>）。
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
