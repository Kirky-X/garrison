//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `strategy` 模块的 inline tests。
//!
//! 从 `mod.rs` 迁移而出（规则 25：mod.rs 接口隔离）。
//! 覆盖权限校验、角色层级、权限缓存、插件钩子、防火墙安全钩子等场景。
//!
//! 注意：引用 `BulwarkFirewallCheckHook` / `LoginContext` 的测试需 cfg 门控
//! （依赖 limiteron / firewall-* / oauth2-server feature）。

use super::mock::MockCacheDao;
use super::*;
use crate::error::BulwarkError;
#[cfg(any(
    feature = "sms-rate-limit",
    feature = "firewall-ratelimit",
    feature = "firewall-bruteforce",
    feature = "firewall-ddos",
    feature = "firewall",
    feature = "oauth2-server"
))]
use crate::strategy::hooks::{
    BulwarkFirewallCheckHook, BulwarkFirewallCheckHookDefault, LoginContext,
};
use std::collections::HashMap;

// ------------------------------------------------------------------------
// MockInterface：模拟业务方实现 BulwarkInterface 回调
// ------------------------------------------------------------------------

/// 测试用 BulwarkInterface mock，基于 HashMap 存储 login_id → 权限/角色列表。
struct MockInterface {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
}

impl MockInterface {
    fn new() -> Self {
        Self {
            permissions: HashMap::new(),
            roles: HashMap::new(),
        }
    }

    /// 设置指定 login_id 的权限列表。
    fn set_permissions(&mut self, login_id: &str, perms: &[&str]) {
        self.permissions.insert(
            login_id.to_string(),
            perms.iter().map(|s| s.to_string()).collect(),
        );
    }

    /// 设置指定 login_id 的角色列表。
    fn set_roles(&mut self, login_id: &str, roles: &[&str]) {
        self.roles.insert(
            login_id.to_string(),
            roles.iter().map(|s| s.to_string()).collect(),
        );
    }
}

#[async_trait]
impl BulwarkInterface for MockInterface {
    async fn get_permission_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
    }

    async fn get_role_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.roles.get(login_id).cloned().unwrap_or_default())
    }
}

/// 辅助函数：创建 BulwarkPermissionStrategyDefault 实例。
fn make_firewall(interface: MockInterface) -> BulwarkPermissionStrategyDefault {
    BulwarkPermissionStrategyDefault::new(Arc::new(interface))
}

// ------------------------------------------------------------------------
// 持有权限返回 true / 未持有返回 false
// ------------------------------------------------------------------------

/// 验证主体持有指定权限时 check_permission 返回 true。
#[tokio::test]
async fn check_permission_held_returns_true() {
    let mut iface = MockInterface::new();
    iface.set_permissions("1001", &["user:read", "user:write"]);
    let fw = make_firewall(iface);

    assert!(
        fw.check_permission("1001", "user:read").await.unwrap(),
        "持有权限应返回 true"
    );
}

/// 验证主体未持有指定权限时 check_permission 返回 false。
#[tokio::test]
async fn check_permission_not_held_returns_false() {
    let mut iface = MockInterface::new();
    iface.set_permissions("1001", &["user:read"]);
    let fw = make_firewall(iface);

    assert!(
        !fw.check_permission("1001", "user:delete").await.unwrap(),
        "未持有权限应返回 false"
    );
}

/// 空字符串抛 InvalidParam。
#[tokio::test]
async fn check_permission_empty_string_errors() {
    let iface = MockInterface::new();
    let fw = make_firewall(iface);

    let result = fw.check_permission("1001", "").await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidParam(_))),
        "空权限字符串应抛 InvalidParam"
    );
}

/// 验证主体无任何权限记录时 check_permission 返回 false（不抛错）。
#[tokio::test]
async fn check_permission_no_record_returns_false() {
    let iface = MockInterface::new();
    let fw = make_firewall(iface);

    assert!(
        !fw.check_permission("9999", "user:read").await.unwrap(),
        "无权限记录的 login_id 应返回 false"
    );
}

// ------------------------------------------------------------------------
// 持有角色返回 true / 未持有返回 false
// ------------------------------------------------------------------------

/// 验证主体持有指定角色时 check_role 返回 true。
#[tokio::test]
async fn check_role_held_returns_true() {
    let mut iface = MockInterface::new();
    iface.set_roles("1001", &["admin", "user"]);
    let fw = make_firewall(iface);

    assert!(
        fw.check_role("1001", "admin").await.unwrap(),
        "持有角色应返回 true"
    );
}

/// 验证主体未持有指定角色时 check_role 返回 false。
#[tokio::test]
async fn check_role_not_held_returns_false() {
    let mut iface = MockInterface::new();
    iface.set_roles("1001", &["user"]);
    let fw = make_firewall(iface);

    assert!(
        !fw.check_role("1001", "admin").await.unwrap(),
        "未持有角色应返回 false"
    );
}

/// 验证空角色字符串返回 Err。
///
/// 与 `check_permission_empty_string_errors` 对称：
/// 空角色字符串应抛 `InvalidParam` 错误。
#[tokio::test]
async fn check_role_empty_string_errors() {
    let iface = MockInterface::new();
    let fw = make_firewall(iface);

    let result = fw.check_role("1001", "").await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidParam(_))),
        "空角色字符串应抛 InvalidParam"
    );
}

// ------------------------------------------------------------------------
// 多角色任一匹配 / 全部匹配
// ------------------------------------------------------------------------

/// 验证 check_role_any：主体持有 roles 中任意一个即返回 true。
#[tokio::test]
async fn check_role_any_match_returns_true() {
    let mut iface = MockInterface::new();
    iface.set_roles("1001", &["admin"]);
    let fw = make_firewall(iface);

    assert!(
        fw.check_role_any("1001", &["admin", "superadmin"])
            .await
            .unwrap(),
        "持有任一角色应返回 true"
    );
}

/// 验证 check_role_any：主体不持有 roles 中任何一个则返回 false。
#[tokio::test]
async fn check_role_any_no_match_returns_false() {
    let mut iface = MockInterface::new();
    iface.set_roles("1001", &["user"]);
    let fw = make_firewall(iface);

    assert!(
        !fw.check_role_any("1001", &["admin", "superadmin"])
            .await
            .unwrap(),
        "不持有任一角色应返回 false"
    );
}

/// 验证 check_role_all：主体持有 roles 中所有角色才返回 true。
#[tokio::test]
async fn check_role_all_all_held_returns_true() {
    let mut iface = MockInterface::new();
    iface.set_roles("1001", &["admin", "user"]);
    let fw = make_firewall(iface);

    assert!(
        fw.check_role_all("1001", &["admin", "user"]).await.unwrap(),
        "持有所有角色应返回 true"
    );
}

/// 主体仅持有部分角色时返回 false。
#[tokio::test]
async fn check_role_all_partial_held_returns_false() {
    let mut iface = MockInterface::new();
    iface.set_roles("1001", &["admin"]);
    let fw = make_firewall(iface);

    assert!(
        !fw.check_role_all("1001", &["admin", "user"]).await.unwrap(),
        "仅持有部分角色应返回 false"
    );
}

/// 验证 check_role_all：空 roles 切片返回 true（空集平凡满足）。
#[tokio::test]
async fn check_role_all_empty_roles_returns_true() {
    let mut iface = MockInterface::new();
    iface.set_roles("1001", &["admin"]);
    let fw = make_firewall(iface);

    assert!(
        fw.check_role_all("1001", &[]).await.unwrap(),
        "空 roles 切片应平凡返回 true"
    );
}

// ------------------------------------------------------------------------
// get_permission_list / get_role_list 回调委托验证
// ------------------------------------------------------------------------

/// 验证 get_permission_list 委托 BulwarkInterface 回调。
#[tokio::test]
async fn get_permission_list_delegates_to_interface() {
    let mut iface = MockInterface::new();
    iface.set_permissions("1001", &["user:read", "user:write"]);
    let fw = make_firewall(iface);

    let perms = fw.get_permission_list("1001").await.unwrap();
    assert_eq!(perms, vec!["user:read", "user:write"]);
}

/// 验证 get_role_list 委托 BulwarkInterface 回调。
#[tokio::test]
async fn get_role_list_delegates_to_interface() {
    let mut iface = MockInterface::new();
    iface.set_roles("1001", &["admin", "user"]);
    let fw = make_firewall(iface);

    let roles = fw.get_role_list("1001").await.unwrap();
    assert_eq!(roles, vec!["admin", "user"]);
}

/// 验证未配置权限的 login_id 返回空列表（不抛错）。
#[tokio::test]
async fn get_permission_list_unknown_login_id_returns_empty() {
    let iface = MockInterface::new();
    let fw = make_firewall(iface);

    let perms = fw.get_permission_list("9999").await.unwrap();
    assert!(perms.is_empty(), "未配置权限的 login_id 应返回空列表");
}

// ------------------------------------------------------------------------
// PermissionChecker 集成测试
// ------------------------------------------------------------------------

/// 可配置的 MockPermissionChecker，返回预设的权限/角色校验结果。
struct MockPermissionChecker {
    perm_result: bool,
}

#[async_trait]
impl PermissionChecker for MockPermissionChecker {
    async fn has_permission(&self, _login_id: &str, _permission: &str) -> BulwarkResult<bool> {
        Ok(self.perm_result)
    }
    async fn has_role(&self, _login_id: &str, _role: &str) -> BulwarkResult<bool> {
        Ok(false)
    }
    async fn check_permission(&self, _login_id: &str, _permission: &str) -> BulwarkResult<()> {
        Ok(())
    }
    async fn check_role(&self, _login_id: &str, _role: &str) -> BulwarkResult<()> {
        Ok(())
    }
    async fn has_any_permission(&self, _login_id: &str, _perms: &[&str]) -> bool {
        false
    }
    async fn has_all_permissions(&self, _login_id: &str, _perms: &[&str]) -> bool {
        false
    }
}

/// 验证注入 PermissionChecker 后 check_permission 委托到它。
#[tokio::test]
async fn check_permission_delegates_to_permission_checker() {
    let iface = MockInterface::new();
    let pc = Arc::new(MockPermissionChecker { perm_result: true });
    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_permission_checker(pc);

    // PermissionChecker 返回 true，即使 interface 中无权限记录
    assert!(
        fw.check_permission("1001", "user:read").await.unwrap(),
        "注入 PermissionChecker 后应委托校验，返回 true"
    );
}

/// 验证 PermissionChecker 返回 false 时 check_permission 返回 false。
#[tokio::test]
async fn check_permission_delegates_returns_false() {
    let iface = MockInterface::new();
    let pc = Arc::new(MockPermissionChecker { perm_result: false });
    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_permission_checker(pc);

    assert!(
        !fw.check_permission("1001", "user:read").await.unwrap(),
        "PermissionChecker 返回 false 时应返回 false"
    );
}

/// 验证未注入 PermissionChecker 时回退到 默认行为（直接查 interface）。
#[tokio::test]
async fn check_permission_without_checker_falls_back_to_interface() {
    let mut iface = MockInterface::new();
    iface.set_permissions("1001", &["user:read"]);
    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface));

    assert!(
        fw.check_permission("1001", "user:read").await.unwrap(),
        "未注入 PermissionChecker 时应回退到 interface 查询"
    );
}

// ------------------------------------------------------------------------
// 层级角色测试
// ------------------------------------------------------------------------

/// 辅助函数：创建带角色层级的 firewall。
fn make_firewall_with_hierarchy(
    interface: MockInterface,
    hierarchy: HashMap<String, Vec<String>>,
) -> BulwarkPermissionStrategyDefault {
    BulwarkPermissionStrategyDefault::new(Arc::new(interface)).with_role_hierarchy(hierarchy)
}

/// 验证层级角色：admin 隐含持有 user。
#[tokio::test]
async fn check_role_hierarchy_admin_implies_user() {
    let mut iface = MockInterface::new();
    iface.set_roles("1001", &["admin"]);
    let mut hierarchy = HashMap::new();
    hierarchy.insert("admin".to_string(), vec!["user".to_string()]);
    let fw = make_firewall_with_hierarchy(iface, hierarchy);

    assert!(
        fw.check_role("1001", "user").await.unwrap(),
        "admin 应隐含持有 user"
    );
    assert!(
        !fw.check_role("1001", "superadmin").await.unwrap(),
        "admin 不隐含 superadmin"
    );
}

/// 验证层级角色多层传递：superadmin → admin → user。
#[tokio::test]
async fn check_role_hierarchy_transitive() {
    let mut iface = MockInterface::new();
    iface.set_roles("1001", &["superadmin"]);
    let mut hierarchy = HashMap::new();
    hierarchy.insert("admin".to_string(), vec!["user".to_string()]);
    hierarchy.insert("superadmin".to_string(), vec!["admin".to_string()]);
    let fw = make_firewall_with_hierarchy(iface, hierarchy);

    assert!(
        fw.check_role("1001", "user").await.unwrap(),
        "superadmin 应多层传递隐含 user"
    );
    assert!(
        fw.check_role("1001", "admin").await.unwrap(),
        "superadmin 应隐含 admin"
    );
}

/// 验证未配置 role_hierarchy 时保持 默认行为。
#[tokio::test]
async fn check_role_without_hierarchy_keeps_legacy_behavior() {
    let mut iface = MockInterface::new();
    iface.set_roles("1001", &["admin"]);
    let fw = make_firewall(iface); // 无 hierarchy

    assert!(
        !fw.check_role("1001", "user").await.unwrap(),
        "未配置 hierarchy 时 admin 不隐含 user（0.1.0 行为）"
    );
}

/// 验证 check_role_any / check_role_all 在层级角色下的行为。
#[tokio::test]
async fn check_role_any_all_with_hierarchy() {
    let mut iface = MockInterface::new();
    iface.set_roles("1001", &["admin"]);
    let mut hierarchy = HashMap::new();
    hierarchy.insert("admin".to_string(), vec!["user".to_string()]);
    let fw = make_firewall_with_hierarchy(iface, hierarchy);

    // admin 隐含 user，所以 check_role_any(["user", "guest"]) 应返回 true
    assert!(
        fw.check_role_any("1001", &["user", "guest"]).await.unwrap(),
        "层级展开后应持有 user，check_role_any 应返回 true"
    );
    // admin 隐含 user，但不含 superadmin，check_role_all 应返回 false
    assert!(
        !fw.check_role_all("1001", &["user", "superadmin"])
            .await
            .unwrap(),
        "层级展开后不含 superadmin，check_role_all 应返回 false"
    );
}

// ------------------------------------------------------------------------
// 插件钩子测试
// ------------------------------------------------------------------------

/// 验证注入 PluginManager 后 check_permission 触发插件钩子。
#[tokio::test]
async fn check_permission_triggers_plugin_hook() {
    let mut iface = MockInterface::new();
    iface.set_permissions("1001", &["user:read"]);
    // BulwarkPluginManager::new() 收集所有 inventory 注册的插件
    let pm = Arc::new(BulwarkPluginManager::new());
    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_plugin_manager(pm);

    // 插件钩子不应中断主流程，校验结果应正常返回
    assert!(
        fw.check_permission("1001", "user:read").await.unwrap(),
        "插件钩子不应影响校验结果"
    );
}

/// 验证插件失败不中断 check_permission 主流程。
///
/// 注意：当前实现遵循 task 21.3（Err → warn 不中断），不实现 spec 的 Override 机制。
#[tokio::test]
async fn check_permission_plugin_failure_does_not_interrupt() {
    let mut iface = MockInterface::new();
    iface.set_permissions("1001", &["user:read"]);
    // PluginManager 包含 ErrPlugin（on_permission_check 返回 Err），
    // 但主流程不应被中断
    let pm = Arc::new(BulwarkPluginManager::new());
    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_plugin_manager(pm);

    assert!(
        fw.check_permission("1001", "user:read").await.unwrap(),
        "插件失败不应中断主流程，校验结果应正常返回 true"
    );
}

// ------------------------------------------------------------------------
// 权限缓存测试
// ------------------------------------------------------------------------

/// 验证 cache_permission 写入 DAO，后续 get_cached_permission 返回缓存值。
#[tokio::test]
async fn cache_permission_writes_and_reads_back() {
    let dao = Arc::new(MockCacheDao::new());
    let iface = MockInterface::new();
    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_dao(dao.clone());

    fw.cache_permission("1001", "user:read", true, 300)
        .await
        .unwrap();

    let cached = fw.get_cached_permission("1001", "user:read").await.unwrap();
    assert_eq!(cached, Some(true), "缓存应命中并返回 true");

    // 验证 key 格式
    let key = "bulwark:perm:cache:1001:user:read";
    assert_eq!(
        dao.get(key).await.unwrap(),
        Some("true".to_string()),
        "DAO 中应存储 key {}",
        key
    );
}

/// 验证 get_cached_permission 未命中时返回 None。
#[tokio::test]
async fn get_cached_permission_miss_returns_none() {
    let dao = Arc::new(MockCacheDao::new());
    let iface = MockInterface::new();
    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_dao(dao);

    let cached = fw
        .get_cached_permission("1001", "user:delete")
        .await
        .unwrap();
    assert!(cached.is_none(), "未缓存的权限应返回 None");
}

/// 验证缓存覆盖：相同 key 的第二次写入覆盖第一次。
#[tokio::test]
async fn cache_permission_overwrite() {
    let dao = Arc::new(MockCacheDao::new());
    let iface = MockInterface::new();
    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_dao(dao);

    // 第一次缓存 true
    fw.cache_permission("1001", "user:read", true, 300)
        .await
        .unwrap();
    assert_eq!(
        fw.get_cached_permission("1001", "user:read").await.unwrap(),
        Some(true)
    );

    // 覆盖为 false
    fw.cache_permission("1001", "user:read", false, 300)
        .await
        .unwrap();
    assert_eq!(
        fw.get_cached_permission("1001", "user:read").await.unwrap(),
        Some(false),
        "覆盖后应返回 false"
    );
}

/// 验证 check_permission 优先读取缓存（短路优化）。
#[tokio::test]
async fn check_permission_uses_cache_short_circuit() {
    let dao = Arc::new(MockCacheDao::new());
    let mut iface = MockInterface::new();
    // interface 中无 user:read 权限
    iface.set_permissions("1001", &[]);
    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_dao(dao.clone());

    // 预先写入缓存 true（与 interface 实际权限矛盾）
    fw.cache_permission("1001", "user:read", true, 300)
        .await
        .unwrap();

    // check_permission 应短路返回缓存值 true，不查询 interface
    assert!(
        fw.check_permission("1001", "user:read").await.unwrap(),
        "应优先返回缓存结果 true，而非查询 interface"
    );
}

// ------------------------------------------------------------------------
// 防火墙安全钩子集成测试
// ------------------------------------------------------------------------

/// 验证未注入 firewall_hook 时 check_login_hooks 为 no-op（向后兼容 0.2.x）。
#[cfg(any(
    feature = "sms-rate-limit",
    feature = "firewall-ratelimit",
    feature = "firewall-bruteforce",
    feature = "firewall-ddos",
    feature = "firewall",
    feature = "oauth2-server"
))]
#[tokio::test]
async fn check_login_hooks_noop_without_hook() {
    let iface = MockInterface::new();
    let fw = make_firewall(iface);
    let ctx = LoginContext::new("1001");

    // 未注入 hook，应直接返回 Ok
    assert!(
        fw.check_login_hooks("1001", &ctx).await.is_ok(),
        "未注入 firewall_hook 时 check_login_hooks 应为 no-op"
    );
}

/// 验证注入 hook 且所有检查通过时 check_login_hooks 返回 Ok。
#[cfg(any(
    feature = "sms-rate-limit",
    feature = "firewall-ratelimit",
    feature = "firewall-bruteforce",
    feature = "firewall-ddos",
    feature = "firewall",
    feature = "oauth2-server"
))]
#[tokio::test]
async fn check_login_hooks_passes_with_hook() {
    let iface = MockInterface::new();
    let hook = Arc::new(BulwarkFirewallCheckHookDefault::new());
    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_firewall_hook(hook);
    let ctx = LoginContext::new("1001");

    // hook 计数器为空，所有检查应通过
    assert!(
        fw.check_login_hooks("1001", &ctx).await.is_ok(),
        "注入 hook 且无失败记录时 check_login_hooks 应返回 Ok"
    );
}

/// 验证 hook 在登录频率超限时阻断 check_login_hooks。
#[cfg(any(
    feature = "sms-rate-limit",
    feature = "firewall-ratelimit",
    feature = "firewall-bruteforce",
    feature = "firewall-ddos",
    feature = "firewall",
    feature = "oauth2-server"
))]
#[tokio::test]
async fn check_login_hooks_blocks_on_frequency_exceeded() {
    let iface = MockInterface::new();
    let hook = Arc::new(BulwarkFirewallCheckHookDefault::new());
    let fw =
        BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_firewall_hook(hook.clone());
    let ctx = LoginContext::new("1001").with_ip("1.2.3.4");

    // 记录 10 次失败（达到阈值）
    for _ in 0..10 {
        hook.record_failure(&ctx).await.unwrap();
    }

    // check_login_hooks 应被 login_frequency hook 阻断
    let result = fw.check_login_hooks("1001", &ctx).await;
    assert!(result.is_err(), "登录频率超限时应被 check_login_hooks 阻断");
    assert!(
        matches!(result.unwrap_err(), BulwarkError::Session(_)),
        "阻断错误应为 Session 类型"
    );
}

/// 验证 hook 在暴力破解超限时阻断 check_login_hooks。
#[cfg(any(
    feature = "sms-rate-limit",
    feature = "firewall-ratelimit",
    feature = "firewall-bruteforce",
    feature = "firewall-ddos",
    feature = "firewall",
    feature = "oauth2-server"
))]
#[tokio::test]
async fn check_login_hooks_blocks_on_brute_force_exceeded() {
    let iface = MockInterface::new();
    let hook = Arc::new(BulwarkFirewallCheckHookDefault::new());
    let fw =
        BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_firewall_hook(hook.clone());
    let ctx = LoginContext::new("1001"); // 无 IP，仅触发暴力破解检测

    // 记录 5 次失败（达到阈值）
    for _ in 0..5 {
        hook.record_failure(&ctx).await.unwrap();
    }

    // check_login_hooks 应被 brute_force hook 阻断
    let result = fw.check_login_hooks("1001", &ctx).await;
    assert!(result.is_err(), "暴力破解超限时应被 check_login_hooks 阻断");
}

/// 验证 with_firewall_hook builder 方法正确注入 hook。
#[cfg(any(
    feature = "sms-rate-limit",
    feature = "firewall-ratelimit",
    feature = "firewall-bruteforce",
    feature = "firewall-ddos",
    feature = "firewall",
    feature = "oauth2-server"
))]
#[tokio::test]
async fn with_firewall_hook_injects_hook() {
    let iface = MockInterface::new();
    let hook = Arc::new(BulwarkFirewallCheckHookDefault::new());
    let fw =
        BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_firewall_hook(hook.clone());

    // 注入后，记录失败并触发检测应能阻断
    let ctx = LoginContext::new("1001").with_ip("9.9.9.9");
    for _ in 0..10 {
        hook.record_failure(&ctx).await.unwrap();
    }
    let result = fw.check_login_hooks("1001", &ctx).await;
    assert!(result.is_err(), "注入 hook 后应能检测到频率超限并阻断");
}

/// 验证 check_login_hooks 按 5 个 hook 顺序调用（login_frequency 先于 brute_force）。
///
/// 当 IP 维度先达阈值时，应优先返回 login_frequency 错误。
#[cfg(any(
    feature = "sms-rate-limit",
    feature = "firewall-ratelimit",
    feature = "firewall-bruteforce",
    feature = "firewall-ddos",
    feature = "firewall",
    feature = "oauth2-server"
))]
#[tokio::test]
async fn check_login_hooks_calls_in_order() {
    use std::sync::atomic::{AtomicU8, Ordering};

    /// 记录调用顺序的测试 hook。
    struct OrderTrackingHook {
        order: Arc<AtomicU8>,
    }

    #[async_trait]
    impl BulwarkFirewallCheckHook for OrderTrackingHook {
        async fn check_login_frequency(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            self.order.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn check_brute_force(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            self.order.fetch_add(2, Ordering::SeqCst);
            Ok(())
        }
        async fn check_geo_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            self.order.fetch_add(4, Ordering::SeqCst);
            Ok(())
        }
        async fn check_token_reuse(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            self.order.fetch_add(8, Ordering::SeqCst);
            Ok(())
        }
        async fn check_device_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            self.order.fetch_add(16, Ordering::SeqCst);
            Ok(())
        }
    }

    let order = Arc::new(AtomicU8::new(0));
    let hook = Arc::new(OrderTrackingHook {
        order: order.clone(),
    });
    let iface = MockInterface::new();
    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_firewall_hook(hook);
    let ctx = LoginContext::new("1001");

    fw.check_login_hooks("1001", &ctx).await.unwrap();

    // 5 个 hook 按序调用：1 + 2 + 4 + 8 + 16 = 31
    assert_eq!(order.load(Ordering::SeqCst), 31, "5 个 hook 应全部按序调用");
}

/// 验证 check_login_hooks 任一 hook Err 立即阻断后续 hook。
#[cfg(any(
    feature = "sms-rate-limit",
    feature = "firewall-ratelimit",
    feature = "firewall-bruteforce",
    feature = "firewall-ddos",
    feature = "firewall",
    feature = "oauth2-server"
))]
#[tokio::test]
async fn check_login_hooks_short_circuits_on_err() {
    use std::sync::atomic::{AtomicU8, Ordering};

    struct ShortCircuitHook {
        called: Arc<AtomicU8>,
    }

    #[async_trait]
    impl BulwarkFirewallCheckHook for ShortCircuitHook {
        async fn check_login_frequency(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            self.called.fetch_add(1, Ordering::SeqCst);
            Err(BulwarkError::Session("frequency blocked".to_string()))
        }
        async fn check_brute_force(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            self.called.fetch_add(2, Ordering::SeqCst);
            Ok(())
        }
        async fn check_geo_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            self.called.fetch_add(4, Ordering::SeqCst);
            Ok(())
        }
        async fn check_token_reuse(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            self.called.fetch_add(8, Ordering::SeqCst);
            Ok(())
        }
        async fn check_device_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            self.called.fetch_add(16, Ordering::SeqCst);
            Ok(())
        }
    }

    let called = Arc::new(AtomicU8::new(0));
    let hook = Arc::new(ShortCircuitHook {
        called: called.clone(),
    });
    let iface = MockInterface::new();
    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_firewall_hook(hook);
    let ctx = LoginContext::new("1001");

    let result = fw.check_login_hooks("1001", &ctx).await;
    assert!(result.is_err(), "应在第一个 hook Err 时阻断");

    // 仅第一个 hook 被调用（值为 1），后续 4 个未调用
    assert_eq!(
        called.load(Ordering::SeqCst),
        1,
        "第一个 hook Err 后应短路，后续 hook 不应被调用"
    );
}

// ========================================================================
// 覆盖率补充：with_listener_manager、缓存写入失败、多 hook 失败
// ========================================================================

/// `with_listener_manager` 注入后 listener_manager 字段为 Some。
///
/// 覆盖行 275-277（builder 方法体）。
#[cfg(feature = "listener")]
#[test]
fn with_listener_manager_sets_field() {
    use crate::listener::BulwarkListenerManager;
    let lm = Arc::new(BulwarkListenerManager::new());
    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(MockInterface::new()))
        .with_listener_manager(lm);
    assert!(
        fw.listener_manager.is_some(),
        "with_listener_manager 后 listener_manager 应为 Some"
    );
}

/// `check_permission` 缓存写入失败时仅 warn 不中断，仍返回正确结果。
///
/// 覆盖行 394-396, 398（缓存写入失败 warn 分支）。
///
/// 使用 FailingDao（set 方法返回 Err）触发缓存写入失败。
#[tokio::test]
async fn check_permission_cache_write_failure_warns_but_returns_result() {
    /// 所有写操作都失败的 DAO
    struct FailingDao;
    #[async_trait]
    impl crate::dao::BulwarkDao for FailingDao {
        async fn get(&self, _key: &str) -> BulwarkResult<Option<String>> {
            Ok(None)
        }
        async fn set(&self, _key: &str, _value: &str, _ttl: u64) -> BulwarkResult<()> {
            Err(BulwarkError::Dao("simulated set failure".to_string()))
        }
        async fn update(&self, _key: &str, _value: &str) -> BulwarkResult<()> {
            Err(BulwarkError::Dao("simulated update failure".to_string()))
        }
        async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
            Err(BulwarkError::Dao("simulated expire failure".to_string()))
        }
        async fn delete(&self, _key: &str) -> BulwarkResult<()> {
            Ok(())
        }
    }

    let mut iface = MockInterface::new();
    iface.set_permissions("1001", &["user:read"]);
    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_dao(Arc::new(FailingDao));
    // 缓存写入失败但 check_permission 仍应返回 true（持有权限）
    let result = fw.check_permission("1001", "user:read").await;
    assert!(
        result.is_ok(),
        "缓存写入失败不应中断 check_permission，实际: {:?}",
        result
    );
    assert!(
        result.unwrap(),
        "持有权限应返回 true（缓存写入失败不影响结果）"
    );
}

/// `check_login_hooks` 第 3 个 hook（check_geo_anomaly）失败时广播 FirewallBlock 并阻断。
///
/// 覆盖行 467-468（第 3 个 hook 失败）+ 490, 492（broadcast_firewall_block）。
///
/// 注意：此测试同时引用 `BulwarkFirewallCheckHook` / `LoginContext`（依赖 firewall/oauth2
/// feature）和 `BulwarkListenerManager`（依赖 listener feature），需双重 cfg 门控。
/// 之前仅 `#[cfg(feature = "listener")]` 导致 listener + 无 firewall 时编译失败。
#[cfg(all(
    feature = "listener",
    any(
        feature = "sms-rate-limit",
        feature = "firewall-ratelimit",
        feature = "firewall-bruteforce",
        feature = "firewall-ddos",
        feature = "firewall",
        feature = "oauth2-server"
    )
))]
#[tokio::test]
async fn check_login_hooks_geo_anomaly_failure_broadcasts_firewall_block() {
    use crate::listener::BulwarkListenerManager;
    let iface = MockInterface::new();
    let lm = Arc::new(BulwarkListenerManager::new());

    struct GeoFailHook;
    #[async_trait]
    impl crate::strategy::BulwarkFirewallCheckHook for GeoFailHook {
        async fn check_login_frequency(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_brute_force(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_geo_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            Err(BulwarkError::Session("geo blocked".to_string()))
        }
    }

    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface))
        .with_firewall_hook(Arc::new(GeoFailHook))
        .with_listener_manager(lm);
    let ctx = LoginContext::new("1001");
    let result = fw.check_login_hooks("1001", &ctx).await;
    assert!(result.is_err(), "geo_anomaly 失败应阻断");
    assert!(
        matches!(result.unwrap_err(), BulwarkError::Session(_)),
        "应返回 Session 错误"
    );
}

/// `check_login_hooks` 第 4 个 hook（check_token_reuse）失败时广播并阻断。
///
/// 覆盖行 471-472（第 4 个 hook 失败）。
///
/// 注意：双重 cfg 门控同上（listener + firewall/oauth2）。
#[cfg(all(
    feature = "listener",
    any(
        feature = "sms-rate-limit",
        feature = "firewall-ratelimit",
        feature = "firewall-bruteforce",
        feature = "firewall-ddos",
        feature = "firewall",
        feature = "oauth2-server"
    )
))]
#[tokio::test]
async fn check_login_hooks_token_reuse_failure_broadcasts() {
    use crate::listener::BulwarkListenerManager;
    let iface = MockInterface::new();
    let lm = Arc::new(BulwarkListenerManager::new());

    struct TokenReuseFailHook;
    #[async_trait]
    impl crate::strategy::BulwarkFirewallCheckHook for TokenReuseFailHook {
        async fn check_login_frequency(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_brute_force(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_geo_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_token_reuse(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            Err(BulwarkError::Session("token reuse blocked".to_string()))
        }
    }

    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface))
        .with_firewall_hook(Arc::new(TokenReuseFailHook))
        .with_listener_manager(lm);
    let ctx = LoginContext::new("1001");
    let result = fw.check_login_hooks("1001", &ctx).await;
    assert!(result.is_err(), "token_reuse 失败应阻断");
}

/// `check_login_hooks` 第 5 个 hook（check_device_anomaly）失败时广播并阻断。
///
/// 覆盖行 475-476（第 5 个 hook 失败）。
///
/// 注意：双重 cfg 门控同上（listener + firewall/oauth2）。
#[cfg(all(
    feature = "listener",
    any(
        feature = "sms-rate-limit",
        feature = "firewall-ratelimit",
        feature = "firewall-bruteforce",
        feature = "firewall-ddos",
        feature = "firewall",
        feature = "oauth2-server"
    )
))]
#[tokio::test]
async fn check_login_hooks_device_anomaly_failure_broadcasts() {
    use crate::listener::BulwarkListenerManager;
    let iface = MockInterface::new();
    let lm = Arc::new(BulwarkListenerManager::new());

    struct DeviceFailHook;
    #[async_trait]
    impl crate::strategy::BulwarkFirewallCheckHook for DeviceFailHook {
        async fn check_login_frequency(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_brute_force(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_geo_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_token_reuse(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_device_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
            Err(BulwarkError::Session("device anomaly blocked".to_string()))
        }
    }

    let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface))
        .with_firewall_hook(Arc::new(DeviceFailHook))
        .with_listener_manager(lm);
    let ctx = LoginContext::new("1001");
    let result = fw.check_login_hooks("1001", &ctx).await;
    assert!(result.is_err(), "device_anomaly 失败应阻断");
}
