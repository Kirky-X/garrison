//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! GarrisonInterface trait — 权限数据回调接口（由业务方实现）。
use crate::error::GarrisonResult;
use async_trait::async_trait;

/// 接口 trait，定义获取权限 / 角色数据的回调。
///
/// 对应 `StpInterface`，由业务方实现以提供权限数据。
///
/// # 数据来源
///
/// 业务方可自由选择数据来源（数据库 / YAML / 内存 / 外部服务等），
/// 框架不假定具体来源。`GarrisonPermissionStrategyDefault` 通过此回调获取数据后做字符串匹配。
#[async_trait]
pub trait GarrisonInterface: Send + Sync {
    /// 获取指定主体的权限列表。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 权限标识字符串列表（如 `["user:read", "user:write"]`）。
    ///
    /// # 错误
    /// - 数据源访问失败：由业务方实现决定具体 `GarrisonError`。
    async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>>;

    /// 获取指定主体的角色列表。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 角色标识字符串列表（如 `["admin", "user"]`）。
    ///
    /// # 错误
    /// - 数据源访问失败：由业务方实现决定具体 `GarrisonError`。
    async fn get_role_list(&self, login_id: &str) -> GarrisonResult<Vec<String>>;

    /// 获取指定主体在特定 `login_type` 下的权限列表。
    ///
    /// 多账号体系下，不同 `login_type`（如 "admin"/"user"/"merchant"）的权限相互隔离。
    /// 业务方可 override 此方法以接入按 `login_type` 隔离的权限数据源。
    ///
    /// # 向后兼容
    ///
    /// 默认实现委托 [`get_permission_list`](Self::get_permission_list)（忽略 `login_type` 参数），
    /// 现有 `GarrisonInterface` 实现者无需修改即可工作。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `login_type`: 登录类型字符串（业务方自定义，如 "admin"/"user"/"merchant"）。
    ///
    /// # 返回
    /// 权限标识字符串列表。
    ///
    /// # 错误
    /// - 数据源访问失败：由业务方实现决定具体 `GarrisonError`。
    async fn get_permission_list_with_type(
        &self,
        login_id: &str,
        _login_type: &str,
    ) -> GarrisonResult<Vec<String>> {
        self.get_permission_list(login_id).await
    }

    /// 获取指定主体在特定 `login_type` 下的角色列表。
    ///
    /// 多账号体系下，不同 `login_type`（如 "admin"/"user"/"merchant"）的角色相互隔离。
    /// 业务方可 override 此方法以接入按 `login_type` 隔离的角色数据源。
    ///
    /// # 向后兼容
    ///
    /// 默认实现委托 [`get_role_list`](Self::get_role_list)（忽略 `login_type` 参数），
    /// 现有 `GarrisonInterface` 实现者无需修改即可工作。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `login_type`: 登录类型字符串（业务方自定义，如 "admin"/"user"/"merchant"）。
    ///
    /// # 返回
    /// 角色标识字符串列表。
    ///
    /// # 错误
    /// - 数据源访问失败：由业务方实现决定具体 `GarrisonError`。
    async fn get_role_list_with_type(
        &self,
        login_id: &str,
        _login_type: &str,
    ) -> GarrisonResult<Vec<String>> {
        self.get_role_list(login_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    /// 最小化 Interface 实现：只实现必需方法，不 override `with_type` 默认方法。
    struct MinimalInterface;

    #[async_trait]
    impl GarrisonInterface for MinimalInterface {
        async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
            Ok(vec![format!("perm:{}:read", login_id)])
        }
        async fn get_role_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
            Ok(vec![format!("role:{}:viewer", login_id)])
        }
    }

    /// `get_permission_list_with_type` 默认实现委托 `get_permission_list`（忽略 login_type）。
    #[tokio::test]
    async fn default_get_permission_list_with_type_delegates() {
        let iface = MinimalInterface;
        let perms = iface
            .get_permission_list_with_type("user1", "admin")
            .await
            .unwrap();
        assert_eq!(
            perms,
            vec!["perm:user1:read"],
            "默认实现应委托 get_permission_list"
        );
    }

    /// `get_role_list_with_type` 默认实现委托 `get_role_list`（忽略 login_type）。
    #[tokio::test]
    async fn default_get_role_list_with_type_delegates() {
        let iface = MinimalInterface;
        let roles = iface
            .get_role_list_with_type("user1", "merchant")
            .await
            .unwrap();
        assert_eq!(
            roles,
            vec!["role:user1:viewer"],
            "默认实现应委托 get_role_list"
        );
    }

    /// `get_permission_list_with_type` 对不同 login_type 返回相同结果（默认忽略 login_type）。
    #[tokio::test]
    async fn default_get_permission_list_with_type_ignores_login_type() {
        let iface = MinimalInterface;
        let p1 = iface
            .get_permission_list_with_type("u1", "admin")
            .await
            .unwrap();
        let p2 = iface
            .get_permission_list_with_type("u1", "user")
            .await
            .unwrap();
        assert_eq!(p1, p2, "默认实现应忽略 login_type 参数");
    }

    /// `get_role_list_with_type` 对不同 login_type 返回相同结果（默认忽略 login_type）。
    #[tokio::test]
    async fn default_get_role_list_with_type_ignores_login_type() {
        let iface = MinimalInterface;
        let r1 = iface.get_role_list_with_type("u1", "admin").await.unwrap();
        let r2 = iface.get_role_list_with_type("u1", "user").await.unwrap();
        assert_eq!(r1, r2, "默认实现应忽略 login_type 参数");
    }
}
