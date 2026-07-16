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

impl Token for SimpleTokenStyle {
    fn generate(&self, login_id: &str, _timeout: i64) -> BulwarkResult<String> {
        Ok(format!("{}-{}", login_id, Uuid::new_v4()))
    }

    fn verify(&self, token: &str) -> BulwarkResult<Option<String>> {
        match token.split_once('-') {
            Some((id_str, uuid_part)) => {
                // 校验 UUID 部分为合法格式，防止任意字符串伪造
                if Uuid::parse_str(uuid_part).is_ok() {
                    Ok(Some(id_str.to_string()))
                } else {
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    fn parse(&self, token: &str) -> BulwarkResult<TokenClaims> {
        match token.split_once('-') {
            Some((id_str, uuid_part)) => {
                // 校验 UUID 部分为合法格式
                if Uuid::parse_str(uuid_part).is_err() {
                    return Err(BulwarkError::Internal(
                        "Simple token 格式错误：UUID 部分无效".to_string(),
                    ));
                }
                // Simple token 不包含过期时间，expire_at 设为 0
                Ok(TokenClaims {
                    login_id: id_str.to_string(),
                    expire_at: 0,
                    device: None,
                })
            },
            None => Err(BulwarkError::Internal(
                "Simple token 格式错误：缺少 '-' 分隔符".to_string(),
            )),
        }
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
            "simple" => Ok(Box::new(SimpleTokenStyle)),
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
