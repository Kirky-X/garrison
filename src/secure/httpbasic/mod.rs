//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! HTTP Basic 认证子模块（RFC 7617）。
//!
//! 对应 Basic 认证能力，
//! 基于 `base64` crate 实现用户名密码的编解码。
//!
//! 所有方法均为关联函数，`HttpBasicAuth` struct 不持有任何状态。

/// Basic 认证凭证，承载解码后的用户名与密码。
///
/// # 安全说明
///
/// - **Debug 脱敏**：[`Debug`] 为手动实现，`pass` 字段输出 `<redacted>`，
/// 防止 `{:?}` / 日志 / panic backtrace 泄露明文密码。
/// - **内存零化**：`pass` 为普通 `String`，**未** 实现 `zeroize` / 自定义 [`Drop`]——
/// 凭证 drop 后其字节可能残留在已释放的堆内存中直至复用（与 `protocol-zeroize`
/// 防护的密钥同级别风险）。因 HTTP Basic 凭证为短生命周期传输凭证，
/// 当前选择文档声明该残留风险而非引入 feature 门控零化；调用方应：
/// (1) 避免 `clone()` 凭证或延长其生命周期；(2) 不将 `pass` 写入日志/持久化存储；
/// (3) 对长期凭证改用框架的 credential 模块（`credential-zeroize` feature 提供
/// `Zeroize + ZeroizeOnDrop`）。
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    /// 用户名。
    pub user: String,
    /// 密码。
    ///
    /// 注意：本字段为 `pub` 以便业务方按需消费凭证；任何代码均可读取明文，
    /// 调用方应遵循最小暴露原则，仅在验证时短暂持有。
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

/// HTTP Basic 认证工具，封装 RFC 7617 编解码逻辑。
///
/// 所有方法为关联函数，无需实例化即可调用：
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
