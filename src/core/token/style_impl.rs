//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! JwtTokenStyle 实现块（从 mod.rs 迁移）。

use super::*;

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
