//! 权限注册表模块（0.5.1 新增，依据 spec permission-registry M3）。
//!
//! 提供声明式 `permission -> required_roles` 映射，启动时通过 `inventory::submit!`
//! 收集编译期注册的权限声明，运行期通过 [`PermissionRegistry::validate`] 校验权限已注册。
//!
//! # 设计
//!
//! - [`PermissionRegistry`]：运行期注册表，封装 `parking_lot::RwLock<HashMap<String, PermissionSpec>>`
//! - [`PermissionSpec`]：权限规格（runtime struct，含 `name` / `required_roles` / `description`）
//! - [`PermissionRegistration`]：inventory 静态注册条目（`&'static str` 字段，编译期注册）
//!
//! # 使用
//!
//! ```ignore
//! // 编译期声明权限
//! inventory::submit! {
//!     PermissionRegistration {
//!         name: "user:read",
//!         required_roles: "admin,user",
//!         description: "读取用户信息",
//!     }
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

use crate::error::{BulwarkError, BulwarkResult};

/// 权限规格，描述单个权限的元数据（runtime struct）。
///
/// 与 [`PermissionRegistration`] 的区别：`PermissionSpec` 拥有 `String` 字段，
/// 用于运行期存储；`PermissionRegistration` 拥有 `&'static str` 字段，
/// 用于编译期 inventory 注册。
#[derive(Debug, Clone)]
pub struct PermissionSpec {
    /// 权限名称（唯一标识，如 `"user:read"`）。
    pub name: String,
    /// 必需角色列表（为空表示无角色要求）。
    pub required_roles: Vec<String>,
    /// 权限描述（人类可读）。
    pub description: String,
}

/// 权限注册条目，用于 `inventory` 编译期注册（依据 spec permission-registry M3）。
///
/// 所有字段为 `&'static str` 以支持编译期常量构造。`required_roles` 为逗号分隔字符串，
/// [`PermissionRegistry::from_inventory`] 时按 `,` split 转换为 `Vec<String>`。
///
/// 通过 `inventory::submit! { PermissionRegistration { ... } }` 注册权限，
/// 运行期通过 `inventory::iter::<PermissionRegistration>()` 遍历。
///
/// 参考 `crate::strategy::firewall::StrategyRegistration` 的 inventory 模式
///（启用 `firewall` feature 时可见）。
pub struct PermissionRegistration {
    /// 权限名称（唯一标识，如 `"user:read"`）。
    pub name: &'static str,
    /// 必需角色列表（逗号分隔，如 `"admin,user"`；空字符串表示无角色要求）。
    pub required_roles: &'static str,
    /// 权限描述（人类可读）。
    pub description: &'static str,
}

// 编译期权限注册收集点
inventory::collect!(PermissionRegistration);

/// 权限注册表，封装 `permission -> required_roles` 映射（依据 spec permission-registry M3）。
///
/// 启动时通过 [`from_inventory`](Self::from_inventory) 收集所有 `inventory::submit!` 注册的
/// [`PermissionRegistration`]，运行期通过 [`validate`](Self::validate) 校验权限已注册。
///
/// 内部用 `parking_lot::RwLock<HashMap<String, PermissionSpec>>` 保护并发访问。
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

    /// 注册单个权限规格。
    ///
    /// # 错误
    /// - `name` 为空 → `BulwarkError::InvalidParam`
    /// - `name` 已注册 → `BulwarkError::InvalidParam`
    pub fn register(&self, spec: PermissionSpec) -> BulwarkResult<()> {
        if spec.name.is_empty() {
            return Err(BulwarkError::InvalidParam(
                "permission name 不能为空".to_string(),
            ));
        }
        let mut map = self.permissions.write();
        if map.contains_key(&spec.name) {
            return Err(BulwarkError::InvalidParam(format!(
                "permission 已注册: {}",
                spec.name
            )));
        }
        map.insert(spec.name.clone(), spec);
        Ok(())
    }

    /// 校验权限是否已注册，返回其 `required_roles`。
    ///
    /// # 错误
    /// - 权限未注册 → `BulwarkError::NotPermission`
    pub fn validate(&self, permission: &str) -> BulwarkResult<Vec<String>> {
        let map = self.permissions.read();
        match map.get(permission) {
            Some(spec) => Ok(spec.required_roles.clone()),
            None => Err(BulwarkError::NotPermission(format!(
                "权限未在注册表中注册: {}",
                permission
            ))),
        }
    }

    /// 列出所有已注册权限规格。
    ///
    /// 返回顺序按 `name` 字典序排列，保证输出稳定（避免 HashMap 迭代顺序不稳定）。
    pub fn list_all(&self) -> Vec<PermissionSpec> {
        let map = self.permissions.read();
        let mut result: Vec<PermissionSpec> = map.values().cloned().collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        result
    }

    /// 从 inventory 收集所有编译期注册的权限声明。
    ///
    /// 遍历 `inventory::iter::<PermissionRegistration>()`，将每个 `PermissionRegistration`
    /// 转换为 [`PermissionSpec`] 并调用 [`register`](Self::register)。
    ///
    /// `required_roles` 字段为逗号分隔字符串（如 `"admin,user"`），按 `,` split 并 trim
    /// 后转换为 `Vec<String>`；空字符串或纯空白项会被过滤。
    ///
    /// # 错误
    /// 仅在 `PermissionRegistration` 字段冲突时返回错误（实际不应发生，因编译期静态注册）。
    pub fn from_inventory() -> BulwarkResult<Self> {
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

    // 测试用 inventory 静态注册项（仅在 test build 中链接进来，覆盖 from_inventory 测试）。
    // 名称加 `test:` 前缀避免与生产代码潜在 submit 项冲突。
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

    // ========================================================================
    // register / validate 测试（依据 spec permission-registry M3）
    // ========================================================================

    /// T057-1: register 单个权限后 validate 命中（spec Scenario）。
    #[test]
    fn register_single_permission_success() {
        let registry = PermissionRegistry::new();
        let spec = make_spec("user:read", vec!["admin"], "读取用户");
        registry.register(spec).expect("register ok");

        let roles = registry.validate("user:read").expect("validate ok");
        assert_eq!(roles, vec!["admin".to_string()]);
    }

    /// T057-2: validate 返回注册时的 required_roles（多角色场景）。
    #[test]
    fn validate_returns_required_roles_when_registered() {
        let registry = PermissionRegistry::new();
        let spec = make_spec("doc:write", vec!["admin", "editor"], "写文档");
        registry.register(spec).expect("register ok");

        let roles = registry.validate("doc:write").expect("validate ok");
        assert_eq!(roles, vec!["admin".to_string(), "editor".to_string()]);
    }

    /// T057-3: validate 未注册的权限返回 NotPermission 错误（spec Scenario）。
    #[test]
    fn validate_returns_error_for_unregistered_permission() {
        let registry = PermissionRegistry::new();
        let result = registry.validate("nonexistent:perm");
        assert!(result.is_err(), "未注册权限应返回错误");
        match result.err() {
            Some(BulwarkError::NotPermission(_)) => {},
            other => panic!("期望 NotPermission，实际: {:?}", other),
        }
    }

    /// T057-4: register 重复同名权限返回错误（spec Scenario）。
    #[test]
    fn register_duplicate_returns_error() {
        let registry = PermissionRegistry::new();
        let spec1 = make_spec("user:delete", vec!["admin"], "删除用户");
        registry.register(spec1).expect("首次 register ok");

        let spec2 = make_spec("user:delete", vec!["superadmin"], "重复注册");
        let result = registry.register(spec2);
        assert!(result.is_err(), "重复注册应返回错误");
    }

    /// T057-5: register 空 name 返回 InvalidParam 错误（spec Scenario）。
    #[test]
    fn register_empty_name_returns_error() {
        let registry = PermissionRegistry::new();
        let spec = make_spec("", vec!["admin"], "空 name");
        let result = registry.register(spec);
        assert!(result.is_err(), "空 name 应返回错误");
        match result.err() {
            Some(BulwarkError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam，实际: {:?}", other),
        }
    }

    /// T057-6: list_all 返回所有已注册权限规格（数量正确）。
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

    /// T057-7: from_inventory 收集 inventory::submit! 静态注册项（依据 spec permission-registry M3）。
    ///
    /// 验证测试模块顶部 `inventory::submit!` 注册的两个测试项被 `from_inventory` 收集。
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

        // 验证 item1 的 required_roles 正确解析
        let item1 = all
            .iter()
            .find(|s| s.name == "test:from_inventory:item1")
            .expect("item1 应存在");
        assert_eq!(
            item1.required_roles,
            vec!["role1".to_string(), "role2".to_string()],
            "item1 required_roles 应正确解析逗号分隔字符串"
        );

        // 验证 item2 的 required_roles 为空
        let item2 = all
            .iter()
            .find(|s| s.name == "test:from_inventory:item2")
            .expect("item2 应存在");
        assert!(
            item2.required_roles.is_empty(),
            "item2 required_roles 应为空"
        );
    }

    /// T057-8: register required_roles 为空时允许注册（某些权限无角色要求）。
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
