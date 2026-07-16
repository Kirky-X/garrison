//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! JWT 协议插件模块。
//!
//! 对应 JWT 协议支持，
//! 基于 `jsonwebtoken` 10 crate 实现签发、校验与刷新。
//!
//! 仅在启用 `protocol-jwt` 特性时编译。

/// RefreshToken Rotation 子模块。
pub mod refresh;

/// JwtHandler 实现（签发/校验/刷新）。
mod handler;

#[cfg(test)]
mod tests;

use jsonwebtoken::Algorithm;
use serde::{Deserialize, Serialize};

/// Bulwark JWT Claims 载荷。
///
/// 字段兼容 0.1.0 `JwtClaims`，0.2.0 扩展 `login_id` 与 `device` 字段，
/// v0.6.3 扩展 `jti`（RFC 7519 §4.1.7）保证同一秒内签发的 token 唯一。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulwarkJwtClaims {
    /// 主体标识（与 login_id 字符串一致）。
    pub sub: String,

    /// 签发时间（Unix 秒）。
    pub iat: i64,

    /// 过期时间（Unix 秒）。
    pub exp: i64,

    /// Bulwark 登录标识（字符串形式，与 sub 一致）。
    pub login_id: String,

    /// 可选设备标识。
    pub device: Option<String>,

    /// JWT 唯一标识（RFC 7519 §4.1.7）。
    ///
    /// `sign` 时自动生成 UUID；旧 token 反序列化时缺失该字段则为 `None`（向后兼容）。
    /// 用于保证同一秒内为同一用户签发的 token 仍唯一，支持 token rotation 语义。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub jti: Option<String>,

    /// Not Before（RFC 7519 §4.1.5）。
    ///
    /// `sign` 时自动设置为当前时间；旧 token 反序列化时缺失该字段则为 `None`（向后兼容）。
    /// `verify` 启用 `validate_nbf = true` 后，`nbf` 为未来时间时拒绝 token（ImmatureSignature）。
    /// `nbf` 为 `None` 时 jsonwebtoken 跳过 nbf 校验（向后兼容旧 token）。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nbf: Option<i64>,
}

/// 0.1.0 兼容别名。
pub type JwtClaims = BulwarkJwtClaims;

/// JWT 处理器，封装密钥与签名算法以供复用。
///
/// 默认采用 HS256 算法，可通过 `with_algorithm` 切换为 HS512 等。
/// 通过 `with_device` 设置设备标识，签发时写入 claims。
pub struct JwtHandler {
    /// 签名密钥。
    pub secret: String,
    /// 签名算法（默认 HS256）。
    pub algorithm: Algorithm,
    /// 可选设备标识（签发时写入 claims）。
    pub device: Option<String>,
}
