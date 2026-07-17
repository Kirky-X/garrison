//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Token 风格实现块（从 mod.rs 迁移，遵守 mod.rs 接口隔离规则 25）。
//!
//! 包含 `UuidTokenStyle` / `Random64TokenStyle` / `SimpleTokenStyle` /
//! `JwtTokenStyle` / `TokenStyleFactory` 的 `impl` 块。

use super::*;
use uuid::Uuid;

// ====================================================================
// UuidTokenStyle
// ====================================================================

impl Token for UuidTokenStyle {
    fn generate(&self, _login_id: &str, _timeout: i64) -> BulwarkResult<String> {
        Ok(Uuid::new_v4().to_string())
    }

    fn verify(&self, _token: &str) -> BulwarkResult<Option<String>> {
        // UUID 无 payload，无法提取 login_id
        Ok(None)
    }

    fn parse(&self, _token: &str) -> BulwarkResult<TokenClaims> {
        Err(BulwarkError::Internal(
            "UUID token 风格不支持 parse（无 payload）".to_string(),
        ))
    }
}

// ====================================================================
// Random64TokenStyle
// ====================================================================

impl Token for Random64TokenStyle {
    fn generate(&self, _login_id: &str, _timeout: i64) -> BulwarkResult<String> {
        // 拼接两个 UUID v4 的 simple 表示（各 32 hex 字符 = 64 字符）
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        Ok(token)
    }

    fn verify(&self, _token: &str) -> BulwarkResult<Option<String>> {
        // 随机 hex 无 payload，无法提取 login_id
        Ok(None)
    }

    fn parse(&self, _token: &str) -> BulwarkResult<TokenClaims> {
        Err(BulwarkError::Internal(
            "random_64 token 风格不支持 parse（无 payload）".to_string(),
        ))
    }
}

// ====================================================================
// SimpleTokenStyle
// ====================================================================

#[cfg(feature = "secure-simple-token")]
impl SimpleTokenStyle {
    /// 计算 HMAC-SHA256 并返回 URL-safe Base64 编码。
    ///
    /// 输入为 `login_id|uuid`（管道分隔），输出为 Base64 编码的 HMAC（43 字符，无 padding）。
    fn compute_hmac(&self, login_id: &str, uuid_part: &str) -> BulwarkResult<String> {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;
        let message = format!("{}|{}", login_id, uuid_part);
        let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes())
            .map_err(|e| BulwarkError::Config(format!("HMAC 密钥长度无效: {}", e)))?;
        mac.update(message.as_bytes());
        // URL-safe Base64 无 padding（43 字符），适合放入 token
        Ok(Self::base64_url_no_pad(&mac.finalize().into_bytes()))
    }

    /// 将字节切片编码为 URL-safe Base64（无 padding）。
    fn base64_url_no_pad(bytes: &[u8]) -> String {
        // 手动实现 URL-safe Base64 无 padding，避免引入额外 base64 依赖
        // （base64 crate 已是 optional dep，但 secure-simple-token feature 未启用它）
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut result = String::with_capacity((bytes.len() * 4).div_ceil(3));
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
            let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            result.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
            result.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                result.push(CHARS[((n >> 6) & 0x3F) as usize] as char);
            }
            if chunk.len() > 2 {
                result.push(CHARS[(n & 0x3F) as usize] as char);
            }
        }
        result
    }
}

#[cfg(feature = "secure-simple-token")]
impl Token for SimpleTokenStyle {
    fn generate(&self, login_id: &str, _timeout: i64) -> BulwarkResult<String> {
        // A11: fail-closed — 空密钥拒绝生成 token
        if self.secret.is_empty() {
            return Err(BulwarkError::Config(
                "SimpleTokenStyle secret 不能为空（A11 fail-closed）".to_string(),
            ));
        }
        let uuid = Uuid::new_v4();
        let uuid_str = uuid.to_string();
        // 格式：<login_id>-<uuid>.<hmac_sha256_base64(secret, login_id|uuid)>
        let hmac = self.compute_hmac(login_id, &uuid_str)?;
        Ok(format!("{}-{}.{}", login_id, uuid_str, hmac))
    }

    fn verify(&self, token: &str) -> BulwarkResult<Option<String>> {
        use subtle::ConstantTimeEq;

        // A11: fail-closed — 空密钥拒绝验证（所有 token 视为无效）
        if self.secret.is_empty() {
            return Ok(None);
        }
        // 格式：<login_id>-<uuid>.<hmac>
        // 先按 '.' 分割出 HMAC 部分，再按 '-' 分割出 login_id 和 uuid
        let (body, hmac_part) = match token.rsplit_once('.') {
            Some((b, h)) => (b, h),
            None => return Ok(None), // 旧格式无 HMAC → 视为无效
        };
        let (login_id, uuid_part) = match body.split_once('-') {
            Some((l, u)) => (l, u),
            None => return Ok(None),
        };
        // 校验 UUID 部分为合法格式
        if Uuid::parse_str(uuid_part).is_err() {
            return Ok(None);
        }
        // 计算期望的 HMAC 并常数时间比较
        let expected_hmac = match self.compute_hmac(login_id, uuid_part) {
            Ok(h) => h,
            Err(_) => return Ok(None),
        };
        // ConstantTimeEq 防止 timing side-channel 攻击
        let ct_result = expected_hmac.as_bytes().ct_eq(hmac_part.as_bytes());
        if bool::from(ct_result) {
            Ok(Some(login_id.to_string()))
        } else {
            Ok(None)
        }
    }

    fn parse(&self, token: &str) -> BulwarkResult<TokenClaims> {
        // A11: fail-closed — 空密钥拒绝解析
        if self.secret.is_empty() {
            return Err(BulwarkError::Config(
                "SimpleTokenStyle secret 不能为空（A11 fail-closed）".to_string(),
            ));
        }
        // 格式：<login_id>-<uuid>.<hmac>
        let (body, hmac_part) = token.rsplit_once('.').ok_or_else(|| {
            BulwarkError::Internal("Simple token 格式错误：缺少 '.' HMAC 分隔符".to_string())
        })?;
        let (id_str, uuid_part) = body.split_once('-').ok_or_else(|| {
            BulwarkError::Internal("Simple token 格式错误：缺少 '-' 分隔符".to_string())
        })?;
        // 校验 UUID 部分
        if Uuid::parse_str(uuid_part).is_err() {
            return Err(BulwarkError::Internal(
                "Simple token 格式错误：UUID 部分无效".to_string(),
            ));
        }
        // 校验 HMAC（常数时间比较）
        use subtle::ConstantTimeEq;
        let expected_hmac = self.compute_hmac(id_str, uuid_part)?;
        let ct_result = expected_hmac.as_bytes().ct_eq(hmac_part.as_bytes());
        if !bool::from(ct_result) {
            return Err(BulwarkError::InvalidToken(
                "Simple token HMAC 校验失败".to_string(),
            ));
        }
        // Simple token 不包含过期时间，expire_at 设为 0
        Ok(TokenClaims {
            login_id: id_str.to_string(),
            expire_at: 0,
            device: None,
        })
    }
}

#[cfg(not(feature = "secure-simple-token"))]
impl Token for SimpleTokenStyle {
    fn generate(&self, _login_id: &str, _timeout: i64) -> BulwarkResult<String> {
        // A11 fail-closed：未启用 secure-simple-token feature 时拒绝生成 token
        Err(BulwarkError::Config(
            "SimpleTokenStyle 需启用 secure-simple-token feature（A11 安全修复）".to_string(),
        ))
    }

    fn verify(&self, _token: &str) -> BulwarkResult<Option<String>> {
        // A11 fail-closed：未启用 feature 时所有 token 视为无效
        Ok(None)
    }

    fn parse(&self, _token: &str) -> BulwarkResult<TokenClaims> {
        Err(BulwarkError::Config(
            "SimpleTokenStyle 需启用 secure-simple-token feature（A11 安全修复）".to_string(),
        ))
    }
}

// ====================================================================
// JwtTokenStyle
// ====================================================================

#[cfg(feature = "protocol-jwt")]
impl JwtTokenStyle {
    /// 创建新的 JWT Token 风格。
    ///
    /// # 参数
    /// - `secret`: 签名密钥。
    pub fn new(secret: &str) -> Self {
        Self {
            handler: crate::protocol::jwt::JwtHandler::new(secret),
        }
    }
}

#[cfg(feature = "protocol-jwt")]
impl Token for JwtTokenStyle {
    fn generate(&self, login_id: &str, timeout: i64) -> BulwarkResult<String> {
        self.handler.sign(login_id, timeout)
    }

    fn verify(&self, token: &str) -> BulwarkResult<Option<String>> {
        match self.handler.verify(token) {
            Ok(claims) => Ok(Some(claims.login_id)),
            Err(_) => Ok(None),
        }
    }

    fn parse(&self, token: &str) -> BulwarkResult<TokenClaims> {
        let claims = self.handler.verify(token)?;
        Ok(TokenClaims {
            login_id: claims.login_id,
            expire_at: claims.exp,
            device: claims.device.clone(),
        })
    }
}

// ====================================================================
// TokenStyleFactory
// ====================================================================

impl TokenStyleFactory {
    /// 依据风格字符串创建 Token 实现。
    ///
    /// # 参数
    /// - `style`: 风格字符串（`"uuid"` / `"random_64"` / `"simple"` / `"jwt"`）。
    /// - `secret`: 签名密钥（仅 `jwt` 风格使用，其他风格忽略）。
    ///
    /// # 返回
    /// - `Ok(Box<dyn Token>)`: 创建成功。
    /// - `Err(BulwarkError::Config)`: 未知风格，消息含 "unknown token_style"。
    #[allow(clippy::new_ret_no_self)]
    pub fn new(style: &str, secret: &str) -> BulwarkResult<Box<dyn Token>> {
        match style {
            "uuid" => Ok(Box::new(UuidTokenStyle)),
            "random_64" => Ok(Box::new(Random64TokenStyle)),
            // A11: SimpleTokenStyle 需传入 secret 用于 HMAC-SHA256 签名
            "simple" => Ok(Box::new(SimpleTokenStyle::new(secret.to_string()))),
            #[cfg(feature = "protocol-jwt")]
            "jwt" => Ok(Box::new(JwtTokenStyle::new(secret))),
            #[cfg(not(feature = "protocol-jwt"))]
            "jwt" => {
                let _ = secret; // 避免 unused 警告（jwt 风格需 protocol-jwt feature）
                Err(BulwarkError::Config(
                    "unknown token_style: jwt（需启用 protocol-jwt feature）".to_string(),
                ))
            },
            other => Err(BulwarkError::Config(format!(
                "unknown token_style: {}",
                other
            ))),
        }
    }
}
