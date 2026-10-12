// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Token 抽象模块：定义 Token 生成 / 验证 / 解析的 trait 与 4 种风格实现
//!（uuid / random_64 / simple / jwt），框架内部经 `Token` trait 切换风格。

use crate::error::{GarrisonError, GarrisonResult};
use serde::{Deserialize, Serialize};

/// Token 解析后的声明（login_id / expire_at / device）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// 登录主体标识。
    pub login_id: String,
    /// 过期时间戳（Unix 秒）。
    pub expire_at: i64,
    /// 设备标识（可选）。
    pub device: Option<String>,
}

/// Token 抽象 trait（生成 / 验证 / 解析三方法）：`verify` 在 token 有效时返回
/// `Ok(Some(login_id))`，无效时返回 `Ok(None)`。
pub trait Token: Send + Sync {
    /// 生成 token，关联指定 login_id 与过期时间（timeout 秒）。
    fn generate(&self, login_id: &str, timeout: i64) -> GarrisonResult<String>;

    /// 生成携带认证方法引用的 token（MFA 因子账本 → amr / auth_time claim）；仅 JWT 风格有
    /// claim 载体（其余风格默认实现忽略二者并委托 [`Token::generate`]，账本仍以会话记录为权威）。
    /// amr 空切片 / auth_time `None` 不写 claim；签发路径应统一经本方法传入账本映射结果
    /// （`crate::stp::mfa::amr_claim`），禁止硬编码 claim。
    fn generate_with_amr(
        &self,
        login_id: &str,
        timeout: i64,
        amr: &[String],
        auth_time: Option<i64>,
    ) -> GarrisonResult<String> {
        let _ = (amr, auth_time);
        self.generate(login_id, timeout)
    }

    /// 校验 token：有效且含 login_id 返回 `Ok(Some(login_id))`，否则 `Ok(None)`（如 UUID 风格）。
    fn verify(&self, token: &str) -> GarrisonResult<Option<String>>;

    /// 解析 token 为 `TokenClaims`；不支持 parse / 过期 / 格式错误返回 `Err(GarrisonError)`。
    fn parse(&self, token: &str) -> GarrisonResult<TokenClaims>;
}

// UuidTokenStyle

/// UUID v4 风格 Token（如 `6e56d6f8-2b31-4d8e-92c3-7a9c8f0d1234`）：不含 login_id / 过期信息，
/// `verify` 始终返回 `Ok(None)`。
#[derive(Debug, Clone, Copy, Default)]
pub struct UuidTokenStyle;

// Random64TokenStyle

/// 64 字符随机 hex 风格 Token：不含 login_id / 过期信息，`verify` 始终返回 `Ok(None)`。
#[derive(Debug, Clone, Copy, Default)]
pub struct Random64TokenStyle;

// SimpleTokenStyle

/// Simple 风格 Token：`<login_id>\x1f<uuid>.<exp>.<hmac_sha256_base64(secret, login_id|uuid|exp)>`。
///
/// HMAC-SHA256 签名防伪造，内嵌 `exp`（Unix 秒）实现 token 级过期（对齐 JWT 语义）。安全模型：
/// 生成用 secret 签名，`timeout <= 0` 拒绝（fail-closed，杜绝无过期时间的永久 token）；验证用
/// `secure::ct_eq::constant_time_eq` 常数时间比较 HMAC（防 timing side-channel），`exp` 过期视为
/// 无效；`secure-simple-token` feature 未启用时 `generate` / `verify` / `parse` 均返回 `Err`。
/// 旧格式（无 HMAC 或无 exp 段）在 `verify` 时返回 `Ok(None)`，用户需重新登录。
#[derive(Clone, Default)]
pub struct SimpleTokenStyle {
    /// HMAC-SHA256 签名密钥（服务端保管，不随 token 下发；仅 `secure-simple-token` 下由 impl 读取）。
    ///
    /// Debug 手动实现脱敏输出 `[REDACTED]`。已知限制：`String` 存储的明文在 `drop` 时不清零，
    /// `Clone` 还会复制出更多副本（增加侧信道泄露面）；严格场景应启用 `protocol-zeroize`
    /// feature 将字段换为 `Zeroizing<String>`（Drop 自动清零），作为独立 change 落地。
    // secret 仅被 style_impl.rs 的 HMAC 路径读取；stub impl 不消费密钥，按 cfg_attr 先例定向豁免 dead_code。
    #[cfg_attr(not(feature = "secure-simple-token"), allow(dead_code))]
    secret: String,
}

impl std::fmt::Debug for SimpleTokenStyle {
    /// 手动实现的 Debug：secret 脱敏输出（derive(Debug) 会打印 HMAC 密钥）。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleTokenStyle")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl SimpleTokenStyle {
    /// 创建 SimpleTokenStyle 实例；`secret` 为空串时 `generate` 会 fail-closed。
    pub fn new(secret: String) -> Self {
        Self { secret }
    }
}

// JwtTokenStyle

/// JWT 风格 Token（`protocol-jwt` feature）：委托 `protocol-jwt::JwtHandler` 实现签发与校验。
#[cfg(feature = "protocol-jwt")]
pub struct JwtTokenStyle {
    /// 内部 JWT 处理器。
    handler: crate::protocol::jwt::JwtHandler,
}

mod style_impl;

// TokenStyleFactory

/// Token 风格工厂，依据 `GarrisonConfig.token_style` 创建对应的 `Token` 实现。
pub struct TokenStyleFactory;

#[cfg(test)]
mod tests;
