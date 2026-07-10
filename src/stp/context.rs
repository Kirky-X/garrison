//! task_local 上下文 — Token 续签结果传递。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

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
