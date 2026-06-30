//! HTTP Basic 认证子模块。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 Basic 认证能力，
//! 基于 `base64` crate 实现用户名密码的编解码。
//!
//! 该模块在 0.1.0 为占位实现，完整功能将在 0.2.0+ 提供。

use crate::error::BulwarkResult;

/// HTTP Basic 认证校验器。
pub struct BasicAuthChecker {
    /// 校验回调占位。
    _inner: (),
}

impl BasicAuthChecker {
    /// 创建新的 Basic 认证校验器。
    pub fn new() -> Self {
        Self { _inner: () }
    }

    /// 解析 Basic 认证头。
    ///
    /// # 参数
    /// - `header`: Authorization 头部值（如 `Basic dXNlcjpwYXNz`）。
    pub fn parse(&self, header: &str) -> BulwarkResult<(String, String)> {
        todo!()
    }

    /// 生成 Basic 认证头。
    ///
    /// # 参数
    /// - `username`: 用户名。
    /// - `password`: 密码。
    pub fn format(&self, username: &str, password: &str) -> BulwarkResult<String> {
        todo!()
    }
}

impl Default for BasicAuthChecker {
    fn default() -> Self {
        Self::new()
    }
}
