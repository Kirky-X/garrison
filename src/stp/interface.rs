// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! GarrisonInterface trait — 权限数据回调接口（由业务方实现）。
use crate::error::GarrisonResult;
use async_trait::async_trait;

/// 权限/角色数据回调接口（对应 `StpInterface`，由业务方实现，数据来源不限：数据库 / YAML / 内存 / 外部服务）。
#[async_trait]
pub trait GarrisonInterface: Send + Sync {
    /// 获取指定主体的权限列表；数据源访问失败由实现方决定具体 `GarrisonError`。
    async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>>;

    /// 获取指定主体的角色列表；数据源访问失败由实现方决定具体 `GarrisonError`。
    async fn get_role_list(&self, login_id: &str) -> GarrisonResult<Vec<String>>;

    /// 获取指定主体在特定 `login_type` 下的权限列表（不同 `login_type` 相互隔离）。
    /// 默认委托 [`get_permission_list`](Self::get_permission_list) 忽略 `login_type`，数据源未按 `login_type` 隔离者无需覆写；`GarrisonPermissionStrategyDefault` 经本方法取数。
    async fn get_permission_list_with_type(
        &self,
        login_id: &str,
        _login_type: &str,
    ) -> GarrisonResult<Vec<String>> {
        self.get_permission_list(login_id).await
    }

    /// 获取指定主体在特定 `login_type` 下的角色列表（不同 `login_type` 相互隔离）。
    /// 默认委托 [`get_role_list`](Self::get_role_list) 忽略 `login_type`，数据源未按 `login_type` 隔离者无需覆写；`check_role` / `check_role_any` / `check_role_all` 均经此路径。
    async fn get_role_list_with_type(
        &self,
        login_id: &str,
        _login_type: &str,
    ) -> GarrisonResult<Vec<String>> {
        self.get_role_list(login_id).await
    }

    /// 获取指定主体在指定租户下的权限列表（租户感知数据源）：请求级租户存在时**优先调用本方法**，覆写者获得真实租户作用域数据，跨租户重名 `login_id`（**租户内**标识）不再互染。
    /// 默认委托 [`get_permission_list`](Self::get_permission_list) 忽略 `tenant_id`，既有实现者行为不变；多租户部署**必须覆写**按租户过滤，否则判定退化为全局共享。
    async fn get_permission_list_in_tenant(
        &self,
        _tenant_id: i64,
        login_id: &str,
    ) -> GarrisonResult<Vec<String>> {
        self.get_permission_list(login_id).await
    }

    /// 获取指定主体在指定租户下的角色列表（租户感知数据源）：`GarrisonPermissionStrategyDefault::check_role_in_tenant` 由本方法驱动，跨租户重名 `login_id`（**租户内**标识）不再互染。
    /// 默认委托 [`get_role_list`](Self::get_role_list) 忽略 `tenant_id`，既有实现者行为不变；多租户部署**必须覆写**按租户过滤，否则判定退化为全局共享。
    async fn get_role_list_in_tenant(
        &self,
        _tenant_id: i64,
        login_id: &str,
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

    /// `get_permission_list_in_tenant` 默认实现委托 `get_permission_list`（忽略租户）。
    #[tokio::test]
    async fn default_get_permission_list_in_tenant_delegates() {
        let iface = MinimalInterface;
        let perms = iface
            .get_permission_list_in_tenant(42, "user1")
            .await
            .unwrap();
        assert_eq!(
            perms,
            vec!["perm:user1:read"],
            "默认实现应委托 get_permission_list（忽略 tenant_id）"
        );
    }

    /// `get_role_list_in_tenant` 默认实现委托 `get_role_list`（忽略租户）。
    #[tokio::test]
    async fn default_get_role_list_in_tenant_delegates() {
        let iface = MinimalInterface;
        let roles = iface.get_role_list_in_tenant(42, "user1").await.unwrap();
        assert_eq!(
            roles,
            vec!["role:user1:viewer"],
            "默认实现应委托 get_role_list（忽略 tenant_id）"
        );
    }
}
