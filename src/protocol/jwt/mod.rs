//! JWT 协议插件模块。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 JWT 协议支持，
//! 基于 `jsonwebtoken` crate 实现签发与校验。
//!
//! 仅在启用 `protocol-jwt` 特性时编译。
//!
//! 该模块在 0.1.0 为占位实现，完整功能将在 0.2.0+ 提供。

use crate::error::BulwarkResult;
use serde::{Deserialize, Serialize};

/// JWT Claims 载荷。
///
/// 0.2.0 扩展 `login_id` 与 `device` 字段以支持 `core-token::JwtTokenStyle` 委托。
/// Task Group 9 将重命名为 `BulwarkJwtClaims` 并完成完整签发/校验实现。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// 主体标识（与 login_id 字符串一致）。
    pub sub: String,

    /// 签发时间（Unix 秒）。
    pub iat: i64,

    /// 过期时间（Unix 秒）。
    pub exp: i64,

    /// Bulwark 登录标识（数值形式，便于 Token trait 提取）。
    pub login_id: i64,

    /// 可选设备标识。
    pub device: Option<String>,
}

/// JWT 处理器，提供签发与校验能力。
pub struct JwtHandler {
    /// 签名密钥。
    pub secret: String,
}

impl JwtHandler {
    /// 创建新的 JWT 处理器。
    ///
    /// # 参数
    /// - `secret`: 签名密钥。
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
        }
    }

    /// 签发 JWT。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `timeout`: 有效期（秒）。
    pub fn sign(&self, _login_id: i64, _timeout: i64) -> BulwarkResult<String> {
        todo!()
    }

    /// 校验 JWT 并返回 Claims。
    ///
    /// # 参数
    /// - `token`: JWT 字符串。
    pub fn verify(&self, _token: &str) -> BulwarkResult<JwtClaims> {
        todo!()
    }
}
