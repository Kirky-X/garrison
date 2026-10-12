// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! HTTP Basic 认证子模块（RFC 7617）：基于 `base64` crate 的用户名密码编解码。
//!
//! 所有方法均为关联函数，`HttpBasicAuth` 不持有任何状态。

/// Basic 认证凭证（解码后的用户名与密码）。
///
/// # 安全说明
///
/// [`Debug`] 手动实现，`pass` 输出 `<redacted>`，防 `{:?}` / 日志 / panic backtrace 泄露明文；
/// `pass` 未实现 `zeroize` / `Drop` 零化，drop 后字节可能残留在堆内存（与 `protocol-zeroize` 同级风险，
/// 因 Basic 凭证短生命周期而仅文档声明）——调用方应避免 `clone()` 或延长生命周期、不写入日志/持久化，
/// 长期凭证改用 `credential-zeroize` feature。
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    /// 用户名。
    pub user: String,
    /// 密码（`pub` 便于业务方消费；明文可被任意代码读取，调用方应最小暴露、仅在验证时短暂持有）。
    pub pass: String,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 手动实现：pass 输出占位符，防止 Debug 输出泄露明文密码
        f.debug_struct("Credential")
            .field("user", &self.user)
            .field("pass", &"<redacted>")
            .finish()
    }
}

/// HTTP Basic 认证工具（RFC 7617 编解码，纯关联函数，无需实例化）。
///
/// ```
/// #[cfg(feature = "protocol-httpbasic")]
/// # {
/// use garrison::secure::httpbasic::HttpBasicAuth;
/// let encoded = HttpBasicAuth::encode("alice", "secret");
/// let cred = HttpBasicAuth::decode(&encoded).unwrap();
/// assert_eq!(cred.user, "alice");
/// assert_eq!(cred.pass, "secret");
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpBasicAuth;

/// `HttpBasicAuth` 实现块（encode / decode / parse_authorization_header）。
pub mod auth;

#[cfg(test)]
mod tests;
