// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! OAuth2 Scope Handler 注册表（`oauth2-scope-handler` feature）：`ScopeHandler` trait + `ScopeRegistry`，在 token 请求前做客户端 scope 策略校验。
//!
//! 设计决策：token 请求时通常尚未解析出 login_id（password 流需先认证、client_credentials 无用户），故 `validate_scope(scope)` 传
//! `login_id = 0` 占位；`ScopeRegistry` 用 `parking_lot::RwLock` 保护 `HashMap<String, Arc<dyn ScopeHandler>>`（支持运行时注册/注销）。

use crate::error::{GarrisonError, GarrisonResult};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// OAuth2 scope 校验处理器：按 scope 字符串与 login_id 决定是否允许。
pub trait ScopeHandler: Send + Sync {
    /// 校验指定 login_id 是否持有指定 scope：拒绝返回 `Ok(false)`（不发 HTTP 请求），出错向上传播（Fail Loud）。
    fn validate(&self, scope: &str, login_id: i64) -> GarrisonResult<bool>;
}

/// Scope 注册表，支持运行时动态注册/查询/移除 handler（`parking_lot::RwLock` 保证并发安全）。
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

    /// 注册 scope handler（同名覆盖）。
    pub fn register(&self, name: &str, handler: Arc<dyn ScopeHandler>) {
        let mut map = self.handlers.write();
        map.insert(name.to_string(), handler);
    }

    /// 移除 scope handler（name 不存在时无操作）。
    pub fn unregister(&self, name: &str) {
        let mut map = self.handlers.write();
        map.remove(name);
    }

    /// 校验指定 scope：未注册返回 `GarrisonError::OAuth2`，handler 错误向上传播。
    ///
    /// 读锁仅在克隆 `Arc` 时持有，不横跨 `handler.validate()` 用户回调——慢 handler 不阻塞
    /// registry 并发读，也避免 handler 内重入 `register` / `unregister` 造成自死锁。
    pub fn validate(&self, scope: &str, login_id: i64) -> GarrisonResult<bool> {
        let handler = {
            let map = self.handlers.read();
            map.get(scope).cloned()
        };
        match handler {
            Some(handler) => handler.validate(scope, login_id),
            None => Err(GarrisonError::OAuth2(format!(
                "oauth2-scope-handler-not-registered::{}",
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
        fn validate(&self, _scope: &str, _login_id: i64) -> GarrisonResult<bool> {
            Ok(self.allowed)
        }
    }

    /// 测试用 ScopeHandler：始终返回错误。
    struct ErrHandler;

    impl ScopeHandler for ErrHandler {
        fn validate(&self, scope: &str, _login_id: i64) -> GarrisonResult<bool> {
            Err(GarrisonError::Internal(format!(
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
        fn validate(&self, scope: &str, login_id: i64) -> GarrisonResult<bool> {
            *self.last_scope.write() = Some(scope.to_string());
            *self.last_login_id.write() = Some(login_id);
            Ok(true)
        }
    }

    // ScopeRegistry 基础测试

    #[test]
    fn register_and_validate_returns_handler_result() {
        let registry = ScopeRegistry::new();
        registry.register("openid", Arc::new(StubHandler { allowed: true }));
        let result = registry.validate("openid", 1001).unwrap();
        assert!(result);
    }

    #[test]
    fn validate_returns_false_when_handler_returns_false() {
        let registry = ScopeRegistry::new();
        registry.register("admin", Arc::new(StubHandler { allowed: false }));
        let result = registry.validate("admin", 1001).unwrap();
        assert!(!result);
    }

    #[test]
    fn validate_unregistered_scope_returns_oauth2_error() {
        let registry = ScopeRegistry::new();
        let result = registry.validate("unregistered_scope", 1001);
        assert!(result.is_err());
        match result.err() {
            Some(GarrisonError::OAuth2(msg)) => {
                assert!(msg.contains("oauth2-scope-handler-not-registered::unregistered_scope"))
            },
            other => panic!("期望 OAuth2 错误，实际: {:?}", other),
        }
    }

    #[test]
    fn handler_error_propagates() {
        let registry = ScopeRegistry::new();
        registry.register("error_scope", Arc::new(ErrHandler));
        let result = registry.validate("error_scope", 1001);
        assert!(result.is_err());
        match result.err() {
            Some(GarrisonError::Internal(msg)) => {
                assert!(msg.contains("handler error for scope: error_scope"))
            },
            other => panic!("期望 Internal 错误，实际: {:?}", other),
        }
    }

    #[test]
    fn concurrent_register_is_thread_safe() {
        let registry = Arc::new(ScopeRegistry::new());
        let mut handles = vec![];
        for i in 0..10 {
            let r = registry.clone();
            handles.push(std::thread::spawn(move || {
                r.register(
                    &format!("scope-{}", i),
                    Arc::new(StubHandler { allowed: true }),
                );
            }));
        }
        for h in handles {
            h.join().expect("线程 panic");
        }
        assert_eq!(registry.len(), 10);
        for i in 0..10 {
            assert!(registry.validate(&format!("scope-{}", i), 1001).unwrap());
        }
    }

    #[test]
    fn register_overrides_existing() {
        let registry = ScopeRegistry::new();
        registry.register("s", Arc::new(StubHandler { allowed: false }));
        assert!(!registry.validate("s", 1).unwrap());
        registry.register("s", Arc::new(StubHandler { allowed: true }));
        assert!(registry.validate("s", 1).unwrap());
    }

    #[test]
    fn unregister_removes_handler() {
        let registry = ScopeRegistry::new();
        registry.register("temp", Arc::new(StubHandler { allowed: true }));
        assert!(registry.validate("temp", 1).is_ok());
        registry.unregister("temp");
        assert!(registry.validate("temp", 1).is_err());
    }

    #[test]
    fn unregister_nonexistent_is_idempotent() {
        let registry = ScopeRegistry::new();
        registry.unregister("never-registered");
        assert!(registry.is_empty());
    }

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

    #[test]
    fn default_equals_new() {
        let r1 = ScopeRegistry::new();
        let r2 = ScopeRegistry::default();
        assert!(r1.is_empty());
        assert!(r2.is_empty());
    }

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

    /// handler 在 validate 期间重入 `register`（写锁）不得死锁：读锁不横跨用户回调。
    #[test]
    fn validate_allows_reentrant_register_without_deadlock() {
        struct ReentrantHandler {
            registry: Arc<ScopeRegistry>,
        }
        impl ScopeHandler for ReentrantHandler {
            fn validate(&self, scope: &str, _login_id: i64) -> GarrisonResult<bool> {
                self.registry.register(
                    &format!("{scope}-nested"),
                    Arc::new(StubHandler { allowed: true }),
                );
                Ok(true)
            }
        }

        let registry = Arc::new(ScopeRegistry::new());
        registry.register(
            "reentrant",
            Arc::new(ReentrantHandler {
                registry: registry.clone(),
            }),
        );
        let result = std::thread::spawn(move || registry.validate("reentrant", 1).unwrap())
            .join()
            .expect("handler 重入 register 不得死锁");
        assert!(result);
    }
}
