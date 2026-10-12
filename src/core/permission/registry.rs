// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 权限注册表模块：提供声明式 `permission -> required_roles` 映射——启动时经
//! `inventory::submit!` 收集编译期注册（[`PermissionRegistration`]，`&'static str` 字段），
//! 运行期 [`PermissionRegistry`] 持 `parking_lot::RwLock<HashMap<String, PermissionSpec>>`
//! 供 [`PermissionRegistry::validate`] 校验；inventory 模式参考
//! `crate::strategy::firewall::StrategyRegistration`（启用 `firewall` 时可见）。
//!
//! # 使用
//!
//! ```ignore
//! // 编译期声明权限
//! inventory::submit! {
//! PermissionRegistration {
//! name: "user:read",
//! required_roles: "admin,user",
//! description: "读取用户信息",
//! }
//! }
//!
//! // 启动时收集所有声明
//! let registry = PermissionRegistry::from_inventory()?;
//! let roles = registry.validate("user:read")?;
//! ```
//!
//! 参考 `crate::strategy::firewall::StrategyRegistration` 的 inventory 模式
//!（启用 `firewall` feature 时可见）。

use std::collections::HashMap;

use parking_lot::RwLock;

use crate::error::{GarrisonError, GarrisonResult};

/// 权限规格（运行期存储，拥有 `String` 字段；编译期注册的 [`PermissionRegistration`]
/// 则为 `&'static str`）。
#[derive(Debug, Clone)]
pub struct PermissionSpec {
    /// 权限名称（唯一标识，如 `"user:read"`）。
    pub name: String,
    /// 必需角色列表（为空表示无角色要求）。
    pub required_roles: Vec<String>,
    /// 权限描述（人类可读）。
    pub description: String,
}

/// 权限注册条目（`inventory` 编译期注册）：字段全为 `&'static str`，`required_roles` 为逗号
/// 分隔字符串，[`PermissionRegistry::from_inventory`] 按 `,` split 为 `Vec<String>`；
/// 经 `inventory::submit!` 注册、`inventory::iter::<PermissionRegistration>()` 遍历。
pub struct PermissionRegistration {
    /// 权限名称（唯一标识，如 `"user:read"`）。
    pub name: &'static str,
    /// 必需角色列表（逗号分隔，如 `"admin,user"`；空字符串表示无角色要求）。
    pub required_roles: &'static str,
    /// 权限描述（人类可读）。
    pub description: &'static str,
}

inventory::collect!(PermissionRegistration);

/// 权限注册表（`permission -> required_roles` 映射）：经 [`from_inventory`](Self::from_inventory)
/// 收集 inventory 注册项，[`validate`](Self::validate) 校验权限；内部 `parking_lot::RwLock` 保护并发。
pub struct PermissionRegistry {
    permissions: RwLock<HashMap<String, PermissionSpec>>,
}

impl PermissionRegistry {
    /// 创建空注册表。
    pub fn new() -> Self {
        Self {
            permissions: RwLock::new(HashMap::new()),
        }
    }

    /// 注册单个权限规格：`name` 为空或已注册均返回 `GarrisonError::InvalidParam`。
    ///
    /// `secure-confusable` feature 启用时先经 `crate::secure::confusable::check_confusable`
    /// 检测 Unicode 同形异义字，可疑字符仅 `tracing::warn` 上报、**不阻止注册**。
    pub fn register(&self, spec: PermissionSpec) -> GarrisonResult<()> {
        if spec.name.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "core-permission-name-empty::".to_string(),
            ));
        }

        // Unicode 同形异义字检测（secure-confusable）：仅 warn 上报，不阻止注册。
        #[cfg(feature = "secure-confusable")]
        {
            let warnings = crate::secure::confusable::check_confusable(&spec.name);
            if !warnings.is_empty() {
                tracing::warn!(
                    permission = %spec.name,
                    warnings = ?warnings,
                    "confusable characters detected in permission name"
                );
            }
        }

        let mut map = self.permissions.write();
        if map.contains_key(&spec.name) {
            return Err(GarrisonError::InvalidParam(format!(
                "core-permission-already-registered::{}",
                spec.name
            )));
        }
        map.insert(spec.name.clone(), spec);
        Ok(())
    }

    /// 校验权限已注册并返回其 `required_roles`；未注册返回 `GarrisonError::InvalidParam`。
    pub fn validate(&self, permission: &str) -> GarrisonResult<Vec<String>> {
        let map = self.permissions.read();
        match map.get(permission) {
            Some(spec) => Ok(spec.required_roles.clone()),
            None => Err(GarrisonError::InvalidParam(format!(
                "core-permission-not-registered::{}",
                permission
            ))),
        }
    }

    /// 列出所有已注册权限规格，按 `name` 字典序排序（保证输出稳定）。
    pub fn list_all(&self) -> Vec<PermissionSpec> {
        let map = self.permissions.read();
        let mut result: Vec<PermissionSpec> = map.values().cloned().collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        result
    }

    /// 从 inventory 收集所有编译期注册声明，转为 [`PermissionSpec`] 并 [`register`](Self::register)；
    /// `required_roles` 按 `,` split + trim（空项过滤），仅在字段冲突时报错（静态注册下不应发生）。
    pub fn from_inventory() -> GarrisonResult<Self> {
        let registry = Self::new();
        for reg in inventory::iter::<PermissionRegistration> {
            let required_roles: Vec<String> = if reg.required_roles.is_empty() {
                Vec::new()
            } else {
                reg.required_roles
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            };
            let spec = PermissionSpec {
                name: reg.name.to_string(),
                required_roles,
                description: reg.description.to_string(),
            };
            registry.register(spec)?;
        }
        Ok(registry)
    }
}

impl Default for PermissionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 测试用 inventory 静态注册项（仅 test build 链接；`test:` 前缀避免与生产 submit 项冲突）。
    inventory::submit! {
        PermissionRegistration {
            name: "test:from_inventory:item1",
            required_roles: "role1,role2",
            description: "test item 1",
        }
    }
    inventory::submit! {
        PermissionRegistration {
            name: "test:from_inventory:item2",
            required_roles: "",
            description: "test item 2 (no roles)",
        }
    }

    /// 构造测试用 PermissionSpec。
    fn make_spec(name: &str, roles: Vec<&str>, desc: &str) -> PermissionSpec {
        PermissionSpec {
            name: name.to_string(),
            required_roles: roles.into_iter().map(String::from).collect(),
            description: desc.to_string(),
        }
    }

    // register / validate 测试

    /// register 单个权限后 validate 命中。
    #[test]
    fn register_single_permission_success() {
        let registry = PermissionRegistry::new();
        let spec = make_spec("user:read", vec!["admin"], "读取用户");
        registry.register(spec).expect("register ok");

        let roles = registry.validate("user:read").expect("validate ok");
        assert_eq!(roles, vec!["admin".to_string()]);
    }

    /// validate 返回注册时的 required_roles（多角色场景）。
    #[test]
    fn validate_returns_required_roles_when_registered() {
        let registry = PermissionRegistry::new();
        let spec = make_spec("doc:write", vec!["admin", "editor"], "写文档");
        registry.register(spec).expect("register ok");

        let roles = registry.validate("doc:write").expect("validate ok");
        assert_eq!(roles, vec!["admin".to_string(), "editor".to_string()]);
    }

    /// validate 未注册的权限返回 InvalidParam 错误。
    #[test]
    fn validate_returns_error_for_unregistered_permission() {
        let registry = PermissionRegistry::new();
        let result = registry.validate("nonexistent:perm");
        assert!(result.is_err(), "未注册权限应返回错误");
        match result.err() {
            Some(GarrisonError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam，实际: {:?}", other),
        }
    }

    /// register 重复同名权限返回错误。
    #[test]
    fn register_duplicate_returns_error() {
        let registry = PermissionRegistry::new();
        let spec1 = make_spec("user:delete", vec!["admin"], "删除用户");
        registry.register(spec1).expect("首次 register ok");

        let spec2 = make_spec("user:delete", vec!["superadmin"], "重复注册");
        let result = registry.register(spec2);
        assert!(result.is_err(), "重复注册应返回错误");
    }

    /// register 空 name 返回 InvalidParam 错误。
    #[test]
    fn register_empty_name_returns_error() {
        let registry = PermissionRegistry::new();
        let spec = make_spec("", vec!["admin"], "空 name");
        let result = registry.register(spec);
        assert!(result.is_err(), "空 name 应返回错误");
        match result.err() {
            Some(GarrisonError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam，实际: {:?}", other),
        }
    }

    /// list_all 返回全部已注册权限规格。
    #[test]
    fn list_all_returns_all_registered() {
        let registry = PermissionRegistry::new();
        registry
            .register(make_spec("a:read", vec!["r"], "read a"))
            .expect("register 1 ok");
        registry
            .register(make_spec("b:write", vec!["w"], "write b"))
            .expect("register 2 ok");
        registry
            .register(make_spec("c:delete", vec!["d"], "delete c"))
            .expect("register 3 ok");

        let all = registry.list_all();
        assert_eq!(all.len(), 3, "应注册 3 个权限");
        let names: Vec<&str> = all.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"a:read"));
        assert!(names.contains(&"b:write"));
        assert!(names.contains(&"c:delete"));
    }

    /// from_inventory 收集测试模块顶部注册的两个静态项。
    #[test]
    fn from_inventory_collects_static_registrations() {
        let registry = PermissionRegistry::from_inventory().expect("from_inventory ok");
        let all = registry.list_all();
        let names: Vec<&str> = all.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"test:from_inventory:item1"),
            "应收集 test:from_inventory:item1，实际: {:?}",
            names
        );
        assert!(
            names.contains(&"test:from_inventory:item2"),
            "应收集 test:from_inventory:item2，实际: {:?}",
            names
        );

        let item1 = all
            .iter()
            .find(|s| s.name == "test:from_inventory:item1")
            .expect("item1 应存在");
        assert_eq!(
            item1.required_roles,
            vec!["role1".to_string(), "role2".to_string()],
            "item1 required_roles 应正确解析逗号分隔字符串"
        );

        let item2 = all
            .iter()
            .find(|s| s.name == "test:from_inventory:item2")
            .expect("item2 应存在");
        assert!(
            item2.required_roles.is_empty(),
            "item2 required_roles 应为空"
        );
    }

    /// required_roles 为空允许注册（某些权限无角色要求）。
    #[test]
    fn register_empty_required_roles_allowed() {
        let registry = PermissionRegistry::new();
        let spec = make_spec("public:health", vec![], "健康检查（无角色要求）");
        registry
            .register(spec)
            .expect("空 required_roles 应允许注册");

        let roles = registry.validate("public:health").expect("validate ok");
        assert!(roles.is_empty(), "无角色要求的权限应返回空 Vec");
    }
}
