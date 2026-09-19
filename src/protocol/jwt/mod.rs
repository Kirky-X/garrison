// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

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

/// Garrison JWT Claims 载荷。
///
/// 标准字段 `sub` / `iat` / `exp` 之外，携带 `login_id` / `device` 扩展字段，
/// 以及 `jti`（RFC 7519 §4.1.7）保证同一秒内签发的 token 唯一。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GarrisonJwtClaims {
    /// 主体标识（与 login_id 字符串一致）。
    pub sub: String,

    /// 签发时间（Unix 秒）。
    pub iat: i64,

    /// 过期时间（Unix 秒）。
    pub exp: i64,

    /// Garrison 登录标识（字符串形式，与 sub 一致）。
    pub login_id: String,

    /// 可选设备标识。
    pub device: Option<String>,

    /// JWT 唯一标识（RFC 7519 §4.1.7）。
    ///
    /// `sign` 时自动生成 UUID；字段为 `Option` 以兼容不含 `jti` 的外部签发 token
    /// （RFC 7519 中 `jti` 本身为可选 claim）。用于保证同一秒内为同一用户签发的
    /// token 仍唯一，支持 token rotation 语义。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub jti: Option<String>,

    /// Not Before（RFC 7519 §4.1.5）。
    ///
    /// `sign` 时自动设置为当前时间。`verify` 启用 `validate_nbf = true` 后，
    /// `nbf` 为未来时间时拒绝 token（ImmatureSignature）。
    /// 字段为 `Option` 以兼容不含 `nbf` 的外部签发 token（RFC 7519 中 `nbf`
    /// 本身为可选 claim）；`nbf` 缺失时 jsonwebtoken 跳过 nbf 校验。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nbf: Option<i64>,
}

/// JWT 处理器，封装密钥与签名算法以供复用。
///
/// 默认采用 HS256 算法，可通过 `with_algorithm` 切换为 HS512 等。
/// 通过 `with_device` 设置设备标识，签发时写入 claims。
pub struct JwtHandler {
    /// 签名密钥。
    ///
    /// # 安全注意
    ///
    /// 任何持有 `JwtHandler` 的代码都能直接读出原始密钥——调用方应将 handler
    /// 视为敏感对象，仅在可信边界内传递，不要写入日志或序列化输出。
    /// Drop 零化仅在 `protocol-zeroize` feature 下生效（见 `handler.rs` 的
    /// `Drop` impl）：未启用该 feature 时，密钥内存随普通 `String` 释放，
    /// 不保证被覆写。
    pub secret: String,
    /// 签名算法（默认 HS256）。
    pub algorithm: Algorithm,
    /// 可选设备标识（签发时写入 claims）。
    pub device: Option<String>,
}
