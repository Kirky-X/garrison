//! OAuth2 Scope Handler 注册表（0.4.0 新增，依据 spec oauth2-scope-handler）。
//!
//! 提供 `ScopeHandler` trait + `ScopeRegistry` 动态注册表，用于在 OAuth2 token
//! 请求前对 scope 进行客户端策略校验（如拒绝过宽 scope、按用户身份限定 scope 集合等）。
//!
//! 仅在启用 `oauth2-scope-handler` feature 时编译。
//!
//! ## 设计决策（依据 spec oauth2-scope-handler）
//!
//! - `ScopeHandler` trait 的 `validate(scope, login_id)` 方法接受 login_id 参数。
//!   但 OAuth2 客户端流程在 token 请求时通常尚未解析出 login_id（password 流需先认证、
//!   client_credentials 流无用户、refresh_token 流需先解码 refresh_token）。
//!   约定：客户端在 token 请求前调用 `validate_scope(scope)` 时传入 `login_id = 0`，
//!   handler 实现可按需通过其他上下文（如 username / client_id）查询真实 login_id。
//!   这是 spec 与 OAuth2 客户端实际语义之间的妥协（Rule 7 已暴露冲突）。
//! - `ScopeRegistry` 用 `parking_lot::RwLock` 保护 `HashMap<String, Arc<dyn ScopeHandler>>`，
//!   与 `BulwarkPluginManager` / `BulwarkListenerManager` 的 `Vec<Arc<dyn T>>` 模式一致（Arc 而非 Box，
//!   因为 handler 可能被多处共享；RwLock 因为支持运行时 register/unregister）。

use crate::error::{BulwarkError, BulwarkResult};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// OAuth2 scope 校验处理器 trait（依据 spec oauth2-scope-handler）。
///
/// 实现方根据 scope 字符串与 login_id 决定是否允许该 scope。
pub trait ScopeHandler: Send + Sync {
    /// 校验指定 login_id 是否持有指定 scope。
    ///
    /// # 返回
    /// - `Ok(true)`: 允许该 scope。
    /// - `Ok(false)`: 拒绝该 scope（不发送 HTTP 请求）。
    /// - `Err(BulwarkError)`: 校验过程出错（向上传播，Fail Loud）。
    fn validate(&self, scope: &str, login_id: i64) -> BulwarkResult<bool>;
}

/// Scope 注册表，支持运行时动态注册/查询/移除 scope handler（依据 spec oauth2-scope-handler）。
///
/// 使用 `parking_lot::RwLock` 保证多线程并发安全。
pub struct ScopeRegistry {
    /// scope 名称 → handler 映射。
    handlers: RwLock<HashMap<String, Arc<dyn ScopeHandler>>>,
}

impl ScopeRegistry {
    /// 创建空的 ScopeRegistry。
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
        }
    }

    /// 注册 scope handler（依据 spec oauth2-scope-handler）。
    ///
    /// 若 name 已存在，覆盖旧 handler。
    pub fn register(&self, name: &str, handler: Arc<dyn ScopeHandler>) {
        let mut map = self.handlers.write();
        map.insert(name.to_string(), handler);
    }

    /// 移除 scope handler（依据 spec oauth2-scope-handler）。
    ///
    /// 若 name 不存在，无操作（幂等）。
    pub fn unregister(&self, name: &str) {
        let mut map = self.handlers.write();
        map.remove(name);
    }

    /// 校验指定 scope 是否允许（依据 spec oauth2-scope-handler）。
    ///
    /// # 返回
    /// - `Ok(true/false)`: 委托 handler 返回结果。
    /// - `Err(BulwarkError::OAuth2)`: scope 未注册。
    /// - `Err(BulwarkError)`: handler 内部错误向上传播。
    pub fn validate(&self, scope: &str, login_id: i64) -> BulwarkResult<bool> {
        let map = self.handlers.read();
        match map.get(scope) {
            Some(handler) => handler.validate(scope, login_id),
            None => Err(BulwarkError::OAuth2(format!(
                "scope handler not registered: {}",
                scope
            ))),
        }
    }

    /// 返回已注册 scope 数量（用于测试与诊断）。
    pub fn len(&self) -> usize {
        self.handlers.read().len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.handlers.read().is_empty()
    }
}

impl Default for ScopeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用 ScopeHandler：根据构造时传入的 allowed 决定返回值。
    struct StubHandler {
        allowed: bool,
    }

    impl ScopeHandler for StubHandler {
        fn validate(&self, _scope: &str, _login_id: i64) -> BulwarkResult<bool> {
            Ok(self.allowed)
        }
    }

    /// 测试用 ScopeHandler：始终返回错误。
    struct ErrHandler;

    impl ScopeHandler for ErrHandler {
        fn validate(&self, scope: &str, _login_id: i64) -> BulwarkResult<bool> {
            Err(BulwarkError::Internal(format!(
                "handler error for scope: {}",
                scope
            )))
        }
    }

    /// 测试用 ScopeHandler：记录调用参数以验证委托。
    struct RecordingHandler {
        last_scope: RwLock<Option<String>>,
        last_login_id: RwLock<Option<i64>>,
    }

    impl ScopeHandler for RecordingHandler {
        fn validate(&self, scope: &str, login_id: i64) -> BulwarkResult<bool> {
            *self.last_scope.write() = Some(scope.to_string());
            *self.last_login_id.write() = Some(login_id);
            Ok(true)
        }
    }

    // ========================================================================
    // ScopeRegistry 基础测试（依据 spec oauth2-scope-handler）
    // ========================================================================

    /// 注册并查询 scope handler 返回 Ok(true)（spec Scenario: 注册并查询）。
    #[test]
    fn register_and_validate_returns_handler_result() {
        let registry = ScopeRegistry::new();
        registry.register("openid", Arc::new(StubHandler { allowed: true }));
        let result = registry.validate("openid", 1001).unwrap();
        assert!(result);
    }

    /// handler 返回 Ok(false) 时 registry 返回 Ok(false)。
    #[test]
    fn validate_returns_false_when_handler_returns_false() {
        let registry = ScopeRegistry::new();
        registry.register("admin", Arc::new(StubHandler { allowed: false }));
        let result = registry.validate("admin", 1001).unwrap();
        assert!(!result);
    }

    /// 未注册的 scope 返回 OAuth2 错误（spec Scenario: 未注册的 scope）。
    #[test]
    fn validate_unregistered_scope_returns_oauth2_error() {
        let registry = ScopeRegistry::new();
        let result = registry.validate("unregistered_scope", 1001);
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::OAuth2(msg)) => {
                assert!(msg.contains("scope handler not registered: unregistered_scope"))
            }
            other => panic!("期望 OAuth2 错误，实际: {:?}", other),
        }
    }

    /// handler 实现返回错误时向上传播（spec Scenario: 错误传播，Fail Loud）。
    #[test]
    fn handler_error_propagates() {
        let registry = ScopeRegistry::new();
        registry.register("error_scope", Arc::new(ErrHandler));
        let result = registry.validate("error_scope", 1001);
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::Internal(msg)) => {
                assert!(msg.contains("handler error for scope: error_scope"))
            }
            other => panic!("期望 Internal 错误，实际: {:?}", other),
        }
    }

    /// 并发注册线程安全（spec Scenario: 并发注册线程安全）。
    #[test]
    fn concurrent_register_is_thread_safe() {
        let registry = Arc::new(ScopeRegistry::new());
        let mut handles = vec![];
        for i in 0..10 {
            let r = registry.clone();
            handles.push(std::thread::spawn(move || {
                r.register(&format!("scope-{}", i), Arc::new(StubHandler { allowed: true }));
            }));
        }
        for h in handles {
            h.join().expect("线程 panic");
        }
        assert_eq!(registry.len(), 10);
        // 全部 scope 可校验
        for i in 0..10 {
            assert!(registry.validate(&format!("scope-{}", i), 1001).unwrap());
        }
    }

    /// register 覆盖同名 handler。
    #[test]
    fn register_overrides_existing() {
        let registry = ScopeRegistry::new();
        registry.register("s", Arc::new(StubHandler { allowed: false }));
        assert!(!registry.validate("s", 1).unwrap());
        // 覆盖
        registry.register("s", Arc::new(StubHandler { allowed: true }));
        assert!(registry.validate("s", 1).unwrap());
    }

    /// unregister 移除 handler，之后 validate 返回未注册错误。
    #[test]
    fn unregister_removes_handler() {
        let registry = ScopeRegistry::new();
        registry.register("temp", Arc::new(StubHandler { allowed: true }));
        assert!(registry.validate("temp", 1).is_ok());
        registry.unregister("temp");
        assert!(registry.validate("temp", 1).is_err());
    }

    /// unregister 未注册的 name 是幂等的（无操作）。
    #[test]
    fn unregister_nonexistent_is_idempotent() {
        let registry = ScopeRegistry::new();
        registry.unregister("never-registered");
        assert!(registry.is_empty());
    }

    /// validate 委托时正确传递 scope 与 login_id 参数。
    #[test]
    fn validate_delegates_with_correct_params() {
        let handler = Arc::new(RecordingHandler {
            last_scope: RwLock::new(None),
            last_login_id: RwLock::new(None),
        });
        let registry = ScopeRegistry::new();
        registry.register("profile", handler.clone());
        registry.validate("profile", 2002).unwrap();
        assert_eq!(handler.last_scope.read().as_ref().unwrap(), "profile");
        assert_eq!(*handler.last_login_id.read(), Some(2002));
    }

    /// Default trait 等价于 new。
    #[test]
    fn default_equals_new() {
        let r1 = ScopeRegistry::new();
        let r2 = ScopeRegistry::default();
        assert!(r1.is_empty());
        assert!(r2.is_empty());
    }

    /// len / is_empty 反映注册状态。
    #[test]
    fn len_and_is_empty_reflect_state() {
        let registry = ScopeRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        registry.register("a", Arc::new(StubHandler { allowed: true }));
        registry.register("b", Arc::new(StubHandler { allowed: true }));
        assert_eq!(registry.len(), 2);
        assert!(!registry.is_empty());
    }
}
