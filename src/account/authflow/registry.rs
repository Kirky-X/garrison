//! FlowRegistry inventory 注册。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 提供认证流程的编译期注册（`inventory::submit!`）与运行期查询/追加。
//!
//! # 编译期注册
//!
//! 通过 [`inventory::submit!`](macro@inventory::submit) 注册 [`FlowRegistration`]，
//! [`FlowRegistry::from_inventory`] 收集所有注册项并构造查询表。
//!
//! # 运行期追加
//!
//! [`FlowRegistry::register`] 可在运行期追加自定义 flow，同名 flow 覆盖默认值。

use super::AuthenticationFlow;
use std::collections::HashMap;

/// 认证流程编译期注册项。
///
/// 通过 `inventory::submit! { FlowRegistration { name, flow } }` 在编译期注册。
pub struct FlowRegistration {
    /// 流程名称（静态字符串）。
    pub name: &'static str,
    /// 流程构造函数（无参数，返回 [`AuthenticationFlow`]）。
    pub flow: fn() -> AuthenticationFlow,
}

inventory::collect!(FlowRegistration);

/// 认证流程注册表。
///
/// 持有 `name → AuthenticationFlow` 映射，支持编译期 inventory 收集与运行期追加。
pub struct FlowRegistry {
    /// 流程映射表。
    flows: HashMap<String, AuthenticationFlow>,
}

impl FlowRegistry {
    /// 从 `inventory` 收集所有编译期注册的 [`FlowRegistration`]，构造注册表。
    ///
    /// 对每个注册项调用 `flow()` 构造 [`AuthenticationFlow`]，以 `name` 为 key 插入。
    pub fn from_inventory() -> Self {
        let mut flows = HashMap::new();
        for registration in inventory::iter::<FlowRegistration> {
            let flow = (registration.flow)();
            flows.insert(flow.name.clone(), flow);
        }
        Self { flows }
    }

    /// 按名称查询流程，返回 `Option<&AuthenticationFlow>`。
    pub fn get(&self, name: &str) -> Option<&AuthenticationFlow> {
        self.flows.get(name)
    }

    /// 运行期注册流程，以 `flow.name` 为 key 插入。
    ///
    /// 同名流程会覆盖已有值（运行期覆盖编译期默认值）。
    pub fn register(&mut self, flow: AuthenticationFlow) {
        self.flows.insert(flow.name.clone(), flow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::authflow::builder::FlowBuilder;

    /// 测试用编译期注册 flow（用于验证 from_inventory 收集）。
    fn test_registry_flow() -> AuthenticationFlow {
        FlowBuilder::new("test-registry-flow")
            .login("password")
            .build()
    }

    inventory::submit! {
        FlowRegistration {
            name: "test-registry-flow",
            flow: test_registry_flow,
        }
    }

    /// inventory 注册：FlowRegistration 通过 submit! 注册后可被 from_inventory 收集
    /// （R-auth-flow-dsl-007）。
    #[test]
    fn inventory_registration_works() {
        let registry = FlowRegistry::from_inventory();
        // test-registry-flow 由本测试模块 submit! 注册
        assert!(registry.get("test-registry-flow").is_some());
    }

    /// from_inventory 收集所有注册 flow（R-auth-flow-dsl-007）。
    #[test]
    fn from_inventory_collects_flows() {
        let registry = FlowRegistry::from_inventory();
        let flow = registry.get("test-registry-flow");
        assert!(flow.is_some());
        let flow = flow.unwrap();
        assert_eq!(flow.name, "test-registry-flow");
        assert_eq!(flow.steps.len(), 1);
    }

    /// get 查询：存在返回 Some，不存在返回 None（R-auth-flow-dsl-007）。
    #[test]
    fn get_returns_none_for_unknown() {
        let registry = FlowRegistry::from_inventory();
        assert!(registry.get("non-existent-flow").is_none());
    }

    /// register 运行期追加 flow 后可被 get 查询（R-auth-flow-dsl-007）。
    #[test]
    fn register_appends_flow() {
        let mut registry = FlowRegistry::from_inventory();
        let custom = FlowBuilder::new("custom-runtime-flow")
            .login("password")
            .mfa(Some("totp"))
            .build();
        registry.register(custom);
        assert!(registry.get("custom-runtime-flow").is_some());
        let flow = registry.get("custom-runtime-flow").unwrap();
        assert_eq!(flow.steps.len(), 2);
    }

    /// 重复注册：register 同名 flow 覆盖旧值（R-auth-flow-dsl-007）。
    #[test]
    fn register_overrides_existing() {
        let mut registry = FlowRegistry::from_inventory();

        // 首次注册
        let original = FlowBuilder::new("override-target")
            .login("password")
            .build();
        registry.register(original);
        assert_eq!(registry.get("override-target").unwrap().steps.len(), 1);

        // 同名覆盖：多步 flow
        let replacement = FlowBuilder::new("override-target")
            .login("password")
            .mfa(Some("totp"))
            .social("wechat")
            .build();
        registry.register(replacement);
        let flow = registry.get("override-target").unwrap();
        assert_eq!(flow.steps.len(), 3);
    }

    /// from_inventory 返回的 registry 初始包含所有编译期注册项
    /// （R-auth-flow-dsl-007 补充：空查询验证）。
    #[test]
    fn from_inventory_initial_state() {
        let registry = FlowRegistry::from_inventory();
        // 至少包含本模块注册的 test-registry-flow
        assert!(registry.get("test-registry-flow").is_some());
    }
}
