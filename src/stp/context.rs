// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! task_local 上下文 — Token 续签结果传递 + CURRENT_TOKEN 跨 spawn 传播。
use super::{GarrisonContext, CURRENT_TOKEN};
use crate::error::{GarrisonError, GarrisonResult};
use std::future::Future;
use std::sync::{Arc, Mutex};

tokio::task_local! {
    /// 当前请求中续签后的新 Token（若有）：middleware 经 [`with_renewed_token_scope`] 置初始 `None`，`check_and_renew` 成功时写 `Some`，请求结束后 middleware 读取并写入响应 Header。
    pub static CURRENT_RENEWED_TOKEN: Arc<Mutex<Option<String>>>;
}

/// 在 `CURRENT_RENEWED_TOKEN` 作用域内执行 `f`（初始 `None`）；Web 框架 middleware 请求开始时调用。
pub async fn with_renewed_token_scope<R>(f: impl std::future::Future<Output = R>) -> R {
    CURRENT_RENEWED_TOKEN
        .scope(Arc::new(Mutex::new(None)), f)
        .await
}

/// 获取续签后的新 Token（若有）；未在 [`with_renewed_token_scope`] 作用域内调用时返回 `None`。
pub fn current_renewed_token() -> Option<String> {
    CURRENT_RENEWED_TOKEN
        .try_get()
        .ok()
        .and_then(|arc| arc.lock().unwrap_or_else(|p| p.into_inner()).clone())
}

/// 设置续签后的新 Token（crate 内部 API）：供 `check_and_renew` 续签成功时调用；未在作用域内为 no-op。
pub(crate) fn set_renewed_token(token: String) {
    if let Ok(arc) = CURRENT_RENEWED_TOKEN.try_get() {
        *arc.lock().unwrap_or_else(|p| p.into_inner()) = Some(token);
    }
}

/// 获取续签后的新 Token（若有）：与 [`current_renewed_token`] 等价，供 middleware 在请求结束后读取续签结果。
pub fn get_renewed_token() -> Option<String> {
    current_renewed_token()
}

/// 清除续签后的新 Token：供 middleware 写入响应后调用，避免泄漏到后续请求；未在作用域内为 no-op。
pub fn clear_renewed_token() {
    if let Ok(arc) = CURRENT_RENEWED_TOKEN.try_get() {
        *arc.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

// GarrisonContext：task_local CURRENT_TOKEN 跨 spawn 传播
//
// 结构体定义在 `super::mod`，本文件只承载 impl；task_local 不自动传播到 `tokio::spawn` 子任务，经 capture/within 手动传播。

impl GarrisonContext {
    /// 捕获当前 task_local 上下文（`CURRENT_TOKEN`）：在父任务中调用，返回的 `GarrisonContext` 可移动到子任务中。
    pub fn capture() -> Self {
        Self {
            token: current_token().ok(),
        }
    }

    /// 在当前 task 恢复上下文执行 `f`：用 task_local::scope 设置 `CURRENT_TOKEN`，结束后自动清除；`capture()` 时无 token 则直接执行 `f`。
    pub async fn within<F, R>(self, f: F) -> R
    where
        F: Future<Output = R>,
    {
        match self.token {
            Some(token) => CURRENT_TOKEN.scope(token, f).await,
            None => f.await,
        }
    }
}

// CURRENT_TOKEN task_local 上下文 API（with_current_token / current_token）
//
// `CURRENT_TOKEN` 定义在 `super::mod`，本节提供作用域设置与读取 API。

/// 设置当前请求的 token 作用域：在 axum middleware 中调用。
pub async fn with_current_token<R>(token: String, f: impl Future<Output = R>) -> R {
    CURRENT_TOKEN.scope(token, f).await
}

/// 获取当前请求的 token（从 task_local 读取）。
///
/// 未在 `with_current_token` 作用域内调用时返回 `GarrisonError::Session`。
#[allow(clippy::map_clone)]
pub fn current_token() -> GarrisonResult<String> {
    CURRENT_TOKEN
        .try_get()
        .map(|t| t.clone())
        .map_err(|_| GarrisonError::Session("stp-context-not-set::".to_string()))
}

// CURRENT_LOGIN_ID task_local 上下文 API（请求内登录身份复用）
// 请求级登录身份缓存：`with_login_id_scope` 由 Web middleware 在请求开始时创建，`check_login` 校验通过后经 [`cache_login_identity`] 写入 `(token, login_id)`；
// `get_login_id` / `check_permission` 在 token 匹配时复用，消除同请求内对 TokenSession 的第二次读取；`logout` / `kickout` / `revoke_token` 成功后按 token 或 login_id 失效，登出后立即回退 DAO 读取。

tokio::task_local! {
    /// 请求级登录身份缓存（`(token, login_id)`）。
    static CURRENT_LOGIN_ID: std::sync::Arc<std::sync::Mutex<Option<(String, String)>>>;
}

/// 在 `CURRENT_LOGIN_ID` 缓存作用域内执行 `f`（初始 `None`）；Web 框架 middleware 请求开始时调用（与 [`with_current_token`] 同层）。
pub async fn with_login_id_scope<R>(f: impl Future<Output = R>) -> R {
    CURRENT_LOGIN_ID.scope(Arc::new(Mutex::new(None)), f).await
}

/// 缓存校验通过的登录身份（crate 内部 API）：供 `check_login` 校验成功后调用，未在作用域内为 no-op。
pub(crate) fn cache_login_identity(token: &str, login_id: &str) {
    if let Ok(arc) = CURRENT_LOGIN_ID.try_get() {
        *arc.lock().unwrap_or_else(|p| p.into_inner()) =
            Some((token.to_string(), login_id.to_string()));
    }
}

/// 读取与 `token` 匹配的缓存登录身份。
///
/// token 不匹配（请求内换绑 token，如 login/refresh 写入新值）时返回 `None`，调用方应回退 DAO 读取；未在作用域内返回 `None`。
pub(crate) fn cached_login_id_for(token: &str) -> Option<String> {
    let arc = CURRENT_LOGIN_ID.try_get().ok()?;
    let guard = arc.lock().unwrap_or_else(|p| p.into_inner());
    let (cached_token, login_id) = guard.as_ref()?;
    (cached_token == token).then(|| login_id.clone())
}

/// 按 token 失效缓存（crate 内部 API）：供 `logout` / `kickout_by_token` / `revoke_token` 成功后调用，保证登出后同请求内 `get_login_id` 立即回退 DAO 读取。
pub(crate) fn invalidate_login_identity_by_token(token: &str) {
    if let Ok(arc) = CURRENT_LOGIN_ID.try_get() {
        let mut guard = arc.lock().unwrap_or_else(|p| p.into_inner());
        if guard.as_ref().map(|(t, _)| t == token).unwrap_or(false) {
            *guard = None;
        }
    }
}

/// 按 login_id 失效缓存（crate 内部 API）：供 `kickout(login_id)` / `logout_by_login_id` 成功后调用（被踢主体可能持有多个 token，按 login_id 匹配清除）。
pub(crate) fn invalidate_login_identity_by_login_id(login_id: &str) {
    if let Ok(arc) = CURRENT_LOGIN_ID.try_get() {
        let mut guard = arc.lock().unwrap_or_else(|p| p.into_inner());
        if guard
            .as_ref()
            .map(|(_, id)| id == login_id)
            .unwrap_or(false)
        {
            *guard = None;
        }
    }
}

// CURRENT_IP task_local 上下文 API（IP 级失败限速，CWE-307）

tokio::task_local! {
    /// 当前请求的客户端 IP，由 Web middleware 经 [`with_current_ip`] 设置（应使用 `extract_client_ip`，含 trusted_proxies 防 X-Forwarded-For 伪造）；供 `check_api_key` 等按 IP 计入暴力破解防护。
    pub static CURRENT_IP: String;
}

/// 设置当前请求的客户端 IP 作用域：在 Web 框架 middleware 中调用（与 [`with_current_token`] 同处注入）。
pub async fn with_current_ip<R>(ip: String, f: impl Future<Output = R>) -> R {
    CURRENT_IP.scope(ip, f).await
}

/// 获取当前请求的客户端 IP（从 task_local 读取）。
///
/// 未在 [`with_current_ip`] 作用域内调用时返回 `None`（IP 级限速降级为不启用，fail-open）。
#[allow(clippy::map_clone)]
pub fn current_ip() -> Option<String> {
    CURRENT_IP.try_get().ok().map(|ip| ip.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 设置 renewed token 后 get_renewed_token 返回 Some(token)。
    #[tokio::test]
    async fn get_renewed_token_returns_some_when_set() {
        with_renewed_token_scope(async {
            set_renewed_token("new-token-123".to_string());
            assert_eq!(
                get_renewed_token(),
                Some("new-token-123".to_string()),
                "设置续签 token 后应返回 Some"
            );
        })
        .await;
    }

    /// 未设置 renewed token（但在 task_local 作用域内）→ 返回 None。
    #[tokio::test]
    async fn get_renewed_token_returns_none_when_not_set() {
        with_renewed_token_scope(async {
            assert_eq!(get_renewed_token(), None, "未设置续签 token 时应返回 None");
        })
        .await;
    }

    /// 调用 clear_renewed_token 后 → 返回 None。
    #[tokio::test]
    async fn get_renewed_token_returns_none_after_clear() {
        with_renewed_token_scope(async {
            set_renewed_token("new-token-456".to_string());
            clear_renewed_token();
            assert_eq!(get_renewed_token(), None, "clear 后应返回 None");
        })
        .await;
    }

    /// 在 task_local 作用域外调用 → 返回 None（不 panic）。
    #[test]
    fn get_renewed_token_returns_none_outside_scope() {
        let result = std::panic::catch_unwind(get_renewed_token);
        assert!(result.is_ok(), "作用域外调用不应 panic");
        assert_eq!(result.unwrap(), None, "作用域外应返回 None");
    }

    /// 设置 token → 获取 → 清除 → 再获取 → None（完整生命周期）。
    #[tokio::test]
    async fn set_get_clear_get_returns_none() {
        with_renewed_token_scope(async {
            set_renewed_token("token-abc".to_string());
            assert_eq!(
                get_renewed_token(),
                Some("token-abc".to_string()),
                "设置后应返回 Some"
            );
            clear_renewed_token();
            assert_eq!(get_renewed_token(), None, "清除后应返回 None");
        })
        .await;
    }

    /// 锁中毒（poisoned）时仍应恢复内部值而非 panic。
    #[tokio::test]
    async fn renewed_token_recovers_from_poisoned_mutex() {
        // 构造一个中毒的 Mutex：在持有锁的线程中 panic
        let poisoned = Arc::new(Mutex::new(Some("kept".to_string())));
        let p2 = poisoned.clone();
        let handle = std::thread::spawn(move || {
            let _guard = p2.lock().unwrap();
            panic!("inject poison");
        });
        let _ = handle.join();
        let got = CURRENT_RENEWED_TOKEN
            .scope(poisoned.clone(), async { current_renewed_token() })
            .await;
        assert_eq!(
            got,
            Some("kept".to_string()),
            "锁中毒时应通过 into_inner 恢复内部值而非 panic"
        );
    }

    /// with_current_ip + current_ip 往返测试。
    #[tokio::test]
    async fn with_current_ip_and_current_ip_roundtrip() {
        let result = with_current_ip("192.168.1.1".to_string(), async { current_ip() }).await;
        assert_eq!(result, Some("192.168.1.1".to_string()));
    }

    /// 未在 with_current_ip 作用域内调用 current_ip 返回 None。
    #[test]
    fn current_ip_outside_scope_returns_none() {
        assert_eq!(current_ip(), None);
    }

    /// set_renewed_token 在作用域外调用为 no-op（不 panic）。
    #[test]
    fn set_renewed_token_outside_scope_is_noop() {
        let result = std::panic::catch_unwind(|| set_renewed_token("tok".to_string()));
        assert!(result.is_ok(), "作用域外 set_renewed_token 不应 panic");
    }

    /// clear_renewed_token 在作用域外调用为 no-op（不 panic）。
    #[test]
    fn clear_renewed_token_outside_scope_is_noop() {
        let result = std::panic::catch_unwind(clear_renewed_token);
        assert!(result.is_ok(), "作用域外 clear_renewed_token 不应 panic");
    }

    /// GarrisonContext::capture 在 with_current_token 作用域内捕获 token。
    #[tokio::test]
    async fn garrison_context_capture_with_token() {
        with_current_token("test-token-xyz".to_string(), async {
            let ctx = GarrisonContext::capture();
            assert_eq!(ctx.token.as_deref(), Some("test-token-xyz"));
        })
        .await;
    }

    /// GarrisonContext::capture 在无 token 作用域时 token=None。
    #[test]
    fn garrison_context_capture_without_token() {
        let ctx = GarrisonContext::capture();
        assert!(ctx.token.is_none(), "无 token 作用域时 token 应为 None");
    }

    /// GarrisonContext::within 恢复捕获的 token。
    #[tokio::test]
    async fn garrison_context_within_restores_token() {
        let ctx = with_current_token("captured-tok".to_string(), async {
            GarrisonContext::capture()
        })
        .await;

        let recovered = ctx.within(async { current_token().ok() }).await;
        assert_eq!(recovered.as_deref(), Some("captured-tok"));
    }

    /// GarrisonContext::within 无 token 时直接执行 f。
    #[tokio::test]
    async fn garrison_context_within_no_token_runs_f() {
        let ctx = GarrisonContext { token: None };
        let result = ctx.within(async { 42 }).await;
        assert_eq!(result, 42, "无 token 时应直接执行 f");
    }
}
