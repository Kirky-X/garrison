//! HTTP Digest 认证子模块。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 Digest 认证能力，
//! 基于 `sha2` / `base64` crate 实现摘要认证。

use crate::error::BulwarkResult;

/// HTTP Digest 认证校验器。
pub struct DigestAuthChecker {
    /// 校验回调占位。
    _inner: (),
}

impl DigestAuthChecker {
    /// 创建新的 Digest 认证校验器。
    pub fn new() -> Self {
        Self { _inner: () }
    }

    /// 生成 Digest 认证挑战（WWW-Authenticate 头部）。
    ///
    /// # 参数
    /// - `realm`: 认证域。
    pub fn challenge(&self, realm: &str) -> BulwarkResult<String> {
        todo!()
    }

    /// 校验 Digest 认证响应。
    ///
    /// # 参数
    /// - `header`: Authorization 头部值。
    /// - `password`: 用户密码（用于计算预期摘要）。
    pub fn verify(&self, header: &str, password: &str) -> BulwarkResult<bool> {
        todo!()
    }
}

impl Default for DigestAuthChecker {
    fn default() -> Self {
        Self::new()
    }
}
