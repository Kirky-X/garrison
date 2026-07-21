//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! WAF 级防火墙（策略层 Hook 链）。
//!
//! 提供 [`WafContext`](crate::strategy::firewall::waf::WafContext) /
//! [`WafVerdict`](crate::strategy::firewall::waf::WafVerdict) /
//! [`WafHook`](crate::strategy::firewall::waf::WafHook) trait +
//! [`WafHookChain`](crate::strategy::firewall::waf::WafHookChain) 短路链。
//!
//! # 设计
//!
//! - [`WafContext`](crate::strategy::firewall::waf::WafContext)：请求内容快照（path / method / host / headers / params），借用引用零拷贝。
//! - [`WafVerdict`](crate::strategy::firewall::waf::WafVerdict)：校验结果（Allow / Deny { reason, hook }）。
//! - [`WafHook`](crate::strategy::firewall::waf::WafHook) trait：每种校验规则实现一个 Hook，返回 `WafVerdict`。
//! - [`WafHookChain`](crate::strategy::firewall::waf::WafHookChain)：按注册顺序执行 Hook，任一 Deny 则短路返回 `GarrisonError::FirewallBlocked`。
//!
//! # 与 web-waf 的区分
//!
//! - `web-waf`（web 层）：`WafRule` trait + `WafConfig`，返回 `GarrisonError::Config`（400）。
//! - `firewall-waf`（strategy 层）：`WafHook` trait + `WafHookChain`，返回 `FirewallBlocked`（403）。
//!
//! # 错误适配
//!
//! 现有 `GarrisonError::FirewallBlocked(String)` 为单字段变体，
//! WAF Hook 链将 hook 名与 reason 编码为 `format!("[{}] {}", hook, reason)`。

use crate::config::GarrisonConfig;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use std::collections::HashSet;

/// WAF 校验上下文，包含请求内容快照（借用引用，零拷贝）。
#[derive(Debug, Clone, Copy)]
pub struct WafContext<'a> {
    /// 请求路径（如 `/api/users/1`）。
    pub path: &'a str,
    /// HTTP 方法（如 `GET`、`POST`）。
    pub method: &'a str,
    /// Host 头（可选）。
    pub host: Option<&'a str>,
    /// 请求头列表（key, value 元组）。
    pub headers: &'a [(String, String)],
    /// 请求参数列表（key, value 元组）。
    pub params: &'a [(String, String)],
}

/// WAF 校验结果。
#[derive(Debug, Clone)]
pub enum WafVerdict {
    /// 放行，继续执行后续 Hook。
    Allow,
    /// 放行并短路，跳过后续所有 Hook（用于白名单匹配）。
    AllowAndSkip,
    /// 拒绝，短路返回 `FirewallBlocked` 错误。
    Deny {
        /// 拒绝原因（写入错误消息）。
        reason: String,
        /// 触发拒绝的 Hook 名称（写入 tracing 日志）。
        hook: &'static str,
    },
}

/// WAF Hook trait，每种校验规则实现一个 Hook。
///
/// 实现方返回 [`WafVerdict::Allow`] 放行（继续后续 Hook），
/// [`WafVerdict::AllowAndSkip`] 放行并短路（跳过后续 Hook），
/// [`WafVerdict::Deny`] 拒绝。
#[async_trait]
pub trait WafHook: Send + Sync {
    /// 返回 Hook 名称（用于日志和错误追踪）。
    fn name(&self) -> &'static str;

    /// 校验请求上下文，返回 [`WafVerdict`]。
    async fn check(&self, ctx: &WafContext<'_>) -> WafVerdict;
}

/// WAF Hook 链，按注册顺序执行，任一 Deny 则短路返回。
pub struct WafHookChain {
    hooks: Vec<Box<dyn WafHook>>,
}

impl WafHookChain {
    /// 创建空的 Hook 链。
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    /// 追加 Hook 到链尾。
    pub fn register(&mut self, hook: Box<dyn WafHook>) {
        self.hooks.push(hook);
    }

    /// 按注册顺序执行所有 Hook，任一 Deny 则短路返回 `FirewallBlocked` 错误，
    /// `AllowAndSkip` 则短路返回 `Ok(())` 跳过后续 Hook。
    ///
    /// Deny 时将 hook 名与 reason 编码为 `format!("[{}] {}", hook, reason)`，
    /// 复用现有 `GarrisonError::FirewallBlocked(String)` 变体。
    pub async fn check(&self, ctx: &WafContext<'_>) -> GarrisonResult<()> {
        for hook in &self.hooks {
            match hook.check(ctx).await {
                WafVerdict::Allow => continue,
                WafVerdict::AllowAndSkip => {
                    tracing::debug!(hook = hook.name(), "WAF whitelist allowed");
                    return Ok(());
                },
                WafVerdict::Deny { reason, hook: name } => {
                    tracing::warn!(hook = name, reason = %reason, "WAF blocked request");
                    return Err(GarrisonError::FirewallBlocked(format!(
                        "[{}] {}",
                        name, reason
                    )));
                },
            }
        }
        Ok(())
    }

    /// 根据配置创建 WAF Hook 链。
    ///
    /// `waf_enabled_hooks` 为空时注册所有可用 Hook。
    /// 每个 Hook 仅在其对应配置非空时注册。
    pub fn from_config(config: &GarrisonConfig) -> Self {
        let mut chain = Self::new();

        let enabled: HashSet<&str> = config
            .waf_enabled_hooks
            .iter()
            .map(|s| s.as_str())
            .collect();
        let all_enabled = enabled.is_empty();

        if (all_enabled || enabled.contains("white_path")) && !config.waf_white_paths.is_empty() {
            chain.register(Box::new(super::waf_hooks::WhitePathHook::new(
                config.waf_white_paths.clone(),
            )));
        }

        if (all_enabled || enabled.contains("black_path")) && !config.waf_black_paths.is_empty() {
            chain.register(Box::new(super::waf_hooks::BlackPathHook::new(
                config.waf_black_paths.clone(),
            )));
        }

        if all_enabled || enabled.contains("danger_char") {
            chain.register(Box::new(super::waf_hooks::DangerCharacterHook::new()));
        }

        if all_enabled || enabled.contains("banned_char") {
            chain.register(Box::new(super::waf_hooks::BannedCharacterHook::new()));
        }

        if all_enabled || enabled.contains("dir_traversal") {
            chain.register(Box::new(super::waf_hooks::DirectoryTraversalHook::new()));
        }

        if (all_enabled || enabled.contains("host")) && !config.waf_allowed_hosts.is_empty() {
            chain.register(Box::new(super::waf_hooks::HostHook::new(
                config.waf_allowed_hosts.clone(),
            )));
        }

        if (all_enabled || enabled.contains("http_method"))
            && !config.waf_allowed_methods.is_empty()
        {
            chain.register(Box::new(super::waf_hooks::HttpMethodHook::new(
                config.waf_allowed_methods.clone(),
            )));
        }

        if (all_enabled || enabled.contains("header")) && !config.waf_banned_headers.is_empty() {
            chain.register(Box::new(super::waf_hooks::HeaderHook::new(
                config.waf_banned_headers.clone(),
            )));
        }

        if (all_enabled || enabled.contains("parameter")) && !config.waf_banned_params.is_empty() {
            chain.register(Box::new(super::waf_hooks::ParameterHook::new(
                config.waf_banned_params.clone(),
            )));
        }

        chain
    }
}

impl Default for WafHookChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // ----------------------------------------------------------------
    // 测试用 Mock Hook
    // ----------------------------------------------------------------

    /// 始终返回 Allow 的 Mock Hook。
    struct AllowHook {
        hook_name: &'static str,
    }

    #[async_trait]
    impl WafHook for AllowHook {
        fn name(&self) -> &'static str {
            self.hook_name
        }
        async fn check(&self, _ctx: &WafContext<'_>) -> WafVerdict {
            WafVerdict::Allow
        }
    }

    /// 始终返回 Deny 的 Mock Hook。
    struct DenyHook {
        hook_name: &'static str,
        deny_reason: String,
    }

    #[async_trait]
    impl WafHook for DenyHook {
        fn name(&self) -> &'static str {
            self.hook_name
        }
        async fn check(&self, _ctx: &WafContext<'_>) -> WafVerdict {
            WafVerdict::Deny {
                reason: self.deny_reason.clone(),
                hook: self.hook_name,
            }
        }
    }

    /// 记录执行顺序的 Mock Hook。
    struct RecordingHook {
        hook_name: &'static str,
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    #[async_trait]
    impl WafHook for RecordingHook {
        fn name(&self) -> &'static str {
            self.hook_name
        }
        async fn check(&self, _ctx: &WafContext<'_>) -> WafVerdict {
            self.log.lock().unwrap().push(self.hook_name);
            WafVerdict::Allow
        }
    }

    /// 构造测试用 WafContext。
    fn make_ctx<'a>() -> WafContext<'a> {
        WafContext {
            path: "/api/test",
            method: "GET",
            host: Some("example.com"),
            headers: &[],
            params: &[],
        }
    }

    // ========================================================================
    // T007: 10 个测试（Red 阶段，register/check 使用 todo!() 会 panic）
    // ========================================================================

    /// 验证空 chain 的 check() 返回 Ok(())。
    #[tokio::test]
    async fn empty_chain_returns_ok() {
        let chain = WafHookChain::new();
        let ctx = make_ctx();
        let result = chain.check(&ctx).await;
        assert!(result.is_ok(), "空 chain 应返回 Ok(())");
    }

    /// 验证全部 Allow 时遍历所有 Hook 后返回 Ok(())。
    #[tokio::test]
    async fn all_allow_returns_ok() {
        let mut chain = WafHookChain::new();
        chain.register(Box::new(AllowHook { hook_name: "a" }));
        chain.register(Box::new(AllowHook { hook_name: "b" }));
        let ctx = make_ctx();
        let result = chain.check(&ctx).await;
        assert!(result.is_ok(), "全部 Allow 时应返回 Ok(())");
    }

    /// 验证任一 Deny 时短路返回 Err，后续 Hook 不执行。
    #[tokio::test]
    async fn deny_short_circuits() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut chain = WafHookChain::new();
        chain.register(Box::new(RecordingHook {
            hook_name: "first",
            log: log.clone(),
        }));
        chain.register(Box::new(DenyHook {
            hook_name: "deny",
            deny_reason: "blocked".to_string(),
        }));
        chain.register(Box::new(RecordingHook {
            hook_name: "third",
            log: log.clone(),
        }));
        let ctx = make_ctx();
        let result = chain.check(&ctx).await;
        assert!(result.is_err(), "Deny 时应返回 Err");
        let executed = log.lock().unwrap();
        assert!(
            executed.contains(&"first") && !executed.contains(&"third"),
            "短路后第三个 Hook 不应执行，实际执行: {:?}",
            executed
        );
    }

    /// 验证多 Hook 按注册顺序执行。
    #[tokio::test]
    async fn multiple_hooks_execute_in_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut chain = WafHookChain::new();
        chain.register(Box::new(RecordingHook {
            hook_name: "first",
            log: log.clone(),
        }));
        chain.register(Box::new(RecordingHook {
            hook_name: "second",
            log: log.clone(),
        }));
        chain.register(Box::new(RecordingHook {
            hook_name: "third",
            log: log.clone(),
        }));
        let ctx = make_ctx();
        chain.check(&ctx).await.unwrap();
        let executed = log.lock().unwrap();
        assert_eq!(
            *executed,
            vec!["first", "second", "third"],
            "Hook 应按注册顺序执行"
        );
    }

    /// 验证 WafContext 字段可直接访问。
    #[test]
    fn waf_context_fields_accessible() {
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        let params = vec![("id".to_string(), "123".to_string())];
        let ctx = WafContext {
            path: "/api/test",
            method: "GET",
            host: Some("example.com"),
            headers: &headers,
            params: &params,
        };
        assert_eq!(ctx.path, "/api/test");
        assert_eq!(ctx.method, "GET");
        assert_eq!(ctx.host, Some("example.com"));
        assert_eq!(ctx.headers.len(), 1);
        assert_eq!(ctx.params.len(), 1);
        assert_eq!(ctx.headers[0].0, "Content-Type");
        assert_eq!(ctx.params[0].1, "123");
    }

    /// 验证 WafVerdict::Allow 可构造。
    #[test]
    fn waf_verdict_allow_constructable() {
        let verdict = WafVerdict::Allow;
        assert!(matches!(verdict, WafVerdict::Allow));
    }

    /// 验证 WafVerdict::Deny { reason, hook } 可构造。
    #[test]
    fn waf_verdict_deny_constructable() {
        let verdict = WafVerdict::Deny {
            reason: "test reason".to_string(),
            hook: "test_hook",
        };
        match verdict {
            WafVerdict::Deny { reason, hook } => {
                assert_eq!(reason, "test reason");
                assert_eq!(hook, "test_hook");
            },
            WafVerdict::Allow => panic!("应为 Deny"),
            WafVerdict::AllowAndSkip => panic!("应为 Deny"),
        }
    }

    /// 验证 hook.name() 返回 &'static str。
    #[test]
    fn hook_name_returns_static_str() {
        let hook = AllowHook { hook_name: "test" };
        let name: &'static str = hook.name();
        assert_eq!(name, "test");
    }

    /// 验证 Deny 时错误信息含 reason。
    #[tokio::test]
    async fn deny_error_contains_reason() {
        let mut chain = WafHookChain::new();
        chain.register(Box::new(DenyHook {
            hook_name: "test_hook",
            deny_reason: "suspicious_path".to_string(),
        }));
        let ctx = make_ctx();
        let result = chain.check(&ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("suspicious_path"),
            "错误消息应含 reason，实际: {}",
            err_msg
        );
    }

    /// 验证 register() 追加 Hook 到 chain。
    #[tokio::test]
    async fn register_appends_hook() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut chain = WafHookChain::new();
        // 注册第一个 Hook
        chain.register(Box::new(RecordingHook {
            hook_name: "first",
            log: log.clone(),
        }));
        // 注册第二个 Hook
        chain.register(Box::new(RecordingHook {
            hook_name: "second",
            log: log.clone(),
        }));
        let ctx = make_ctx();
        chain.check(&ctx).await.unwrap();
        let executed = log.lock().unwrap();
        assert_eq!(executed.len(), 2, "应执行 2 个 Hook");
        assert_eq!(executed[0], "first", "第一个 Hook 应先执行");
        assert_eq!(executed[1], "second", "第二个 Hook 应后执行");
    }

    // ========================================================================
    // T-CONV-001: WafHookChain::from_config 测试（4 个）
    // ========================================================================

    /// 验证空配置不注册任何 Hook。
    #[tokio::test]
    async fn from_config_empty_registers_none() {
        let mut config = GarrisonConfig::default_config();
        config.waf_enabled_hooks = Vec::new();
        config.waf_white_paths = Vec::new();
        config.waf_black_paths = Vec::new();
        config.waf_allowed_hosts = Vec::new();
        config.waf_allowed_methods = Vec::new();
        config.waf_banned_headers = Vec::new();
        config.waf_banned_params = Vec::new();

        let chain = WafHookChain::from_config(&config);
        let ctx = make_ctx();
        assert!(chain.check(&ctx).await.is_ok(), "空配置应不注册任何 Hook");
    }

    /// 验证全量 Hook 注册（空 enabled_hooks = 全部启用）。
    #[tokio::test]
    async fn from_config_all_enabled_registers_all_hooks() {
        let mut config = GarrisonConfig::default_config();
        config.waf_enabled_hooks = Vec::new();
        config.waf_white_paths = vec!["/api".to_string()];
        config.waf_black_paths = vec!["/admin".to_string()];
        config.waf_allowed_hosts = vec!["example.com".to_string()];
        config.waf_allowed_methods = vec!["GET".to_string()];
        config.waf_banned_headers = vec!["X-Blocked".to_string()];
        config.waf_banned_params = vec!["secret".to_string()];

        let chain = WafHookChain::from_config(&config);

        // 白名单路径 → AllowAndSkip 短路放行
        let ctx = make_ctx();
        assert!(chain.check(&ctx).await.is_ok(), "白名单路径应放行");

        // 黑名单路径 → Deny
        let ctx = WafContext {
            path: "/admin/secret",
            method: "GET",
            host: Some("example.com"),
            headers: &[],
            params: &[],
        };
        assert!(chain.check(&ctx).await.is_err(), "黑名单路径应拦截");
    }

    /// 验证选择性启用 Hook（仅 danger_char + host）。
    #[tokio::test]
    async fn from_config_selective_hooks() {
        let mut config = GarrisonConfig::default_config();
        config.waf_enabled_hooks = vec!["danger_char".to_string(), "host".to_string()];
        config.waf_allowed_hosts = vec!["example.com".to_string()];

        let chain = WafHookChain::from_config(&config);

        // danger_char 应拦截 //
        let ctx = WafContext {
            path: "/api//test",
            method: "GET",
            host: Some("example.com"),
            headers: &[],
            params: &[],
        };
        assert!(chain.check(&ctx).await.is_err(), "danger_char 应拦截 //");

        // host 应拦截非白名单域名
        let ctx = WafContext {
            path: "/api/test",
            method: "GET",
            host: Some("evil.com"),
            headers: &[],
            params: &[],
        };
        assert!(chain.check(&ctx).await.is_err(), "host 应拦截非白名单域名");

        // 正常请求应放行
        let ctx = make_ctx();
        assert!(chain.check(&ctx).await.is_ok(), "正常请求应放行");
    }

    /// 验证 banned_char + dir_traversal 接线正确。
    #[tokio::test]
    async fn from_config_banned_char_and_dir_traversal() {
        let mut config = GarrisonConfig::default_config();
        config.waf_enabled_hooks = vec!["banned_char".to_string(), "dir_traversal".to_string()];

        let chain = WafHookChain::from_config(&config);

        // dir_traversal 应拦截 ../
        let ctx = WafContext {
            path: "/api/../etc",
            method: "GET",
            host: Some("example.com"),
            headers: &[],
            params: &[],
        };
        assert!(chain.check(&ctx).await.is_err(), "dir_traversal 应拦截 ../");

        // 正常路径应放行
        let ctx = make_ctx();
        assert!(chain.check(&ctx).await.is_ok(), "正常路径应放行");
    }
}
