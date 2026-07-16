//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! HTTP Basic 认证子模块（RFC 7617）。
//!
//! 对应 Basic 认证能力，
//! 基于 `base64` crate 实现用户名密码的编解码。
//!
//! 所有方法均为关联函数，`HttpBasicAuth` struct 不持有任何状态。

/// Basic 认证凭证，承载解码后的用户名与密码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// 用户名。
    pub user: String,
    /// 密码。
    pub pass: String,
}

/// HTTP Basic 认证工具，封装 RFC 7617 编解码逻辑。
///
/// 所有方法为关联函数，无需实例化即可调用：
///
/// ```
/// #[cfg(feature = "secure-httpbasic")]
/// # {
/// use bulwark::secure::httpbasic::HttpBasicAuth;
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
