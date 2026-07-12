//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! task_local 上下文 — Token 续签结果传递。
use std::sync::{Arc, Mutex};

tokio::task_local! {
    /// 当前请求中续签后的新 Token（若有）。
    ///
    /// 由 Web 框架 middleware 在请求开始时通过 [`with_renewed_token_scope`] 设置初始值 `None`，
    /// `check_and_renew` 在续签成功时通过 [`set_renewed_token`] 写入 `Some(new_token)`，
    /// Web 框架在请求结束后通过 [`current_renewed_token`] 读取并写入响应 Header。
    ///
    /// # 生命周期
    ///
    /// ```text
    /// Request → middleware sets scope(None)
    ///        → handler calls check_login → check_and_renew writes Some(token)
    ///        → middleware reads current_renewed_token() → writes X-Bulwark-Renewed-Token
    /// Response sent
    /// ```
    pub static CURRENT_RENEWED_TOKEN: Arc<Mutex<Option<String>>>;
}

/// 在 `CURRENT_RENEWED_TOKEN` 作用域内执行 `f`，初始值为 `None`。
///
/// Web 框架 middleware 在请求开始时调用：
/// ```ignore
/// let result = with_renewed_token_scope(async { handler(req).await }).await;
/// if let Some(new_token) = current_renewed_token() {
///     response.headers_mut().insert("X-Bulwark-Renewed-Token", new_token.parse().unwrap());
/// }
/// ```
pub async fn with_renewed_token_scope<R>(f: impl std::future::Future<Output = R>) -> R {
    CURRENT_RENEWED_TOKEN
        .scope(Arc::new(Mutex::new(None)), f)
        .await
}

/// 获取续签后的新 Token（若有）。
///
/// 未在 [`with_renewed_token_scope`] 作用域内调用时返回 `None`。
pub fn current_renewed_token() -> Option<String> {
    CURRENT_RENEWED_TOKEN
        .try_get()
        .ok()
        .and_then(|arc| arc.lock().unwrap().clone())
}

/// 设置续签后的新 Token（crate 内部 API）。
///
/// 供 `check_and_renew` 在续签成功时调用。未在 [`with_renewed_token_scope`]
/// 作用域内时为 no-op（不影响 `check_login` 返回值）。
pub(crate) fn set_renewed_token(token: String) {
    if let Ok(arc) = CURRENT_RENEWED_TOKEN.try_get() {
        *arc.lock().unwrap() = Some(token);
    }
}

/// 获取续签后的新 Token（若有）。
///
/// 与 [`current_renewed_token`] 等价，供 middleware 在请求结束后读取续签结果。
/// 未在 [`with_renewed_token_scope`] 作用域内调用时返回 `None`（不 panic）。
pub fn get_renewed_token() -> Option<String> {
    current_renewed_token()
}

/// 清除续签后的新 Token。
///
/// 供 middleware 在将续签 Token 写入响应后调用，避免泄漏到后续请求。
/// 未在 [`with_renewed_token_scope`] 作用域内调用时为 no-op。
pub fn clear_renewed_token() {
    if let Ok(arc) = CURRENT_RENEWED_TOKEN.try_get() {
        *arc.lock().unwrap() = None;
    }
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
        // 在 task_local 作用域外调用，不应 panic
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
}
