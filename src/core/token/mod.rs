//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Token 抽象模块，定义 Token 生成/验证/解析的 trait 与多种风格实现。
//!
//! 对应 Token 风格切换能力，
//! 0.2.0 将 token 逻辑独立为 `core-token` 模块，
//! 框架内部通过 `Token` trait 实现多种 token 风格切换。
//!
//! 支持 4 种风格：uuid / random_64 / simple / jwt。

use crate::error::{BulwarkError, BulwarkResult};
use serde::{Deserialize, Serialize};

/// Token 声明信息，承载 token 解析后的声明。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// 登录主体标识。
    pub login_id: String,
    /// 过期时间戳（Unix 秒）。
    pub expire_at: i64,
    /// 设备标识（可选）。
    pub device: Option<String>,
}

/// Token 抽象 trait，定义 token 生成、验证与解析的契约。
///
/// 实现方需提供 `generate`、`verify`、`parse` 三个方法。
/// `verify` 在 token 有效时返回 `Ok(Some(login_id))`，无效时返回 `Ok(None)`。
pub trait Token: Send + Sync {
    /// 生成 token，关联指定 login_id 与过期时间。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `timeout`: 有效期（秒）。
    fn generate(&self, login_id: &str, timeout: i64) -> BulwarkResult<String>;

    /// 校验 token，返回关联的 login_id（如果 token 有效且可解析）。
    ///
    /// # 返回
    /// - `Ok(Some(login_id))`: token 有效且包含 login_id。
    /// - `Ok(None)`: token 无效或不包含 login_id（如 UUID 风格）。
    fn verify(&self, token: &str) -> BulwarkResult<Option<String>>;

    /// 解析 token 为 `TokenClaims`。
    ///
    /// # 返回
    /// - `Ok(TokenClaims)`: 解析成功。
    /// - `Err(BulwarkError)`: 解析失败（token 风格不支持 parse / token 过期 / 格式错误）。
    fn parse(&self, token: &str) -> BulwarkResult<TokenClaims>;
}

// ====================================================================
// UuidTokenStyle
// ====================================================================

/// UUID v4 风格 Token。
///
/// 生成标准 UUID v4 格式 token（如 `6e56d6f8-2b31-4d8e-92c3-7a9c8f0d1234`）。
/// UUID 不包含 login_id 或过期信息，`verify` 始终返回 `Ok(None)`。
#[derive(Debug, Clone, Copy, Default)]
pub struct UuidTokenStyle;

// ====================================================================
// Random64TokenStyle
// ====================================================================

/// 64 字符随机 hex 风格 Token。
///
/// 生成 64 字符随机十六进制串，多次调用返回不同 token。
/// 不包含 login_id 或过期信息，`verify` 始终返回 `Ok(None)`。
#[derive(Debug, Clone, Copy, Default)]
pub struct Random64TokenStyle;

// ====================================================================
// SimpleTokenStyle
// ====================================================================

/// Simple 风格 Token（A11 安全修复版）。
///
/// 格式为 `<login_id>-<uuid>.<hmac_sha256_base64(secret, login_id|uuid)>`，
/// 通过 HMAC-SHA256 签名防止 token 伪造（CRITICAL 漏洞修复）。
///
/// # 安全模型（A11）
///
/// - **生成**：服务端用 `secret` 对 `login_id|uuid` 计算 HMAC-SHA256，附加到 token 末尾
/// - **验证**：用 `subtle::ConstantTimeEq` 常数时间比较 HMAC，防止 timing side-channel
/// - **fail-closed**：`secure-simple-token` feature 未启用时，`generate` 返回 `Err`，
///   杜绝无签名的不安全 token 流入生产环境
///
/// # Feature 依赖
///
/// 需启用 `secure-simple-token` feature（已包含在 `auth-server` 中）。
/// 未启用时 `generate` / `verify` / `parse` 均返回 `Err`。
///
/// # 迁移说明
///
/// 旧格式 `<login_id>-<uuid>`（无 HMAC）的 token 在 `verify` 时返回 `Ok(None)`，
/// 视为无效 token，用户需重新登录获取新格式 token。
#[derive(Debug, Clone, Default)]
pub struct SimpleTokenStyle {
    /// HMAC-SHA256 签名密钥（服务端保管，不随 token 下发）。
    ///
    /// 仅在启用 `secure-simple-token` feature 时由 `Token` impl 读取；
    /// 未启用 feature 时为 dead code，此处 allow 以避免 feature-gated 警告。
    #[allow(dead_code)]
    secret: String,
}

impl SimpleTokenStyle {
    /// 创建 SimpleTokenStyle 实例。
    ///
    /// # 参数
    /// - `secret`: HMAC-SHA256 签名密钥。空串时返回实例但 `generate` 会 fail-closed。
    pub fn new(secret: String) -> Self {
        Self { secret }
    }
}

// ====================================================================
// JwtTokenStyle
// ====================================================================

/// JWT 风格 Token。
///
/// 委托 `protocol-jwt::JwtHandler` 实现签发与校验。
/// 仅在启用 `protocol-jwt` feature 时编译。
#[cfg(feature = "protocol-jwt")]
pub struct JwtTokenStyle {
    /// 内部 JWT 处理器。
    handler: crate::protocol::jwt::JwtHandler,
}

mod style_impl;

// ====================================================================
// TokenStyleFactory
// ====================================================================

/// Token 风格工厂，依据 `BulwarkConfig.token_style` 创建对应的 `Token` 实现。
pub struct TokenStyleFactory;

#[cfg(test)]
mod tests;
