//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! JwtHandler 实现：JWT 签发、校验、刷新。
//!
//! 类型定义见 [`JwtHandler`](crate::protocol::jwt::JwtHandler)。

use crate::error::{BulwarkError, BulwarkResult};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{BulwarkJwtClaims, JwtHandler};

impl JwtHandler {
    /// 创建新的 JWT 处理器，默认采用 HS256 算法。
    ///
    /// # 参数
    /// - `secret`: 签名密钥（空字符串将在 `sign` 时拒绝）。
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            algorithm: Algorithm::HS256,
            device: None,
        }
    }

    /// 切换签名算法。
    ///
    /// # 参数
    /// - `algorithm`: 算法（如 `Algorithm::HS512`）。
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// 设置设备标识。
    ///
    /// 签发时写入 claims 的 `device` 字段。
    ///
    /// # 参数
    /// - `device`: 设备标识。
    pub fn with_device(mut self, device: impl Into<String>) -> Self {
        self.device = Some(device.into());
        self
    }

    /// 签发 JWT。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `timeout`: 有效期（秒），不可为负数。
    ///
    /// # 返回
    /// - `Ok(String)`: JWT 字符串（三段 Base64URL 通过 `.` 连接）。
    /// - `Err(BulwarkError::Config)`: 密钥为空或 timeout 为负。
    /// - `Err(BulwarkError::Internal)`: 签发失败。
    pub fn sign(&self, login_id: impl Into<String>, timeout: i64) -> BulwarkResult<String> {
        let login_id: String = login_id.into();
        if self.secret.is_empty() {
            return Err(BulwarkError::Config("JWT secret 不能为空".to_string()));
        }
        if timeout < 0 {
            return Err(BulwarkError::Config(format!(
                "timeout 不能为负数: {}",
                timeout
            )));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| BulwarkError::Internal(format!("系统时间错误: {}", e)))?
            .as_secs() as i64;
        let claims = BulwarkJwtClaims {
            sub: login_id.clone(),
            iat: now,
            exp: now + timeout,
            login_id,
            device: self.device.clone(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            nbf: Some(now), // vuln-0019 修复：签发时设置 nbf，verify 时强制校验
        };
        let header = Header::new(self.algorithm);
        let key = EncodingKey::from_secret(self.secret.as_bytes());
        encode(&header, &claims, &key)
            .map_err(|e| BulwarkError::Internal(format!("JWT 签发失败: {}", e)))
    }

    /// 校验 JWT 并返回 Claims。
    ///
    /// # 参数
    /// - `token`: JWT 字符串。
    ///
    /// # 返回
    /// - `Ok(BulwarkJwtClaims)`: 校验成功。
    /// - `Err(BulwarkError::Config)`: secret 为空。
    /// - `Err(BulwarkError::ExpiredToken)`: token 已过期。
    /// - `Err(BulwarkError::InvalidToken)`: 签名/格式/算法校验失败。
    pub fn verify(&self, token: &str) -> BulwarkResult<BulwarkJwtClaims> {
        if self.secret.is_empty() {
            return Err(BulwarkError::Config("JWT secret 不能为空".to_string()));
        }
        let key = DecodingKey::from_secret(self.secret.as_bytes());
        let mut validation = Validation::new(self.algorithm);
        validation.validate_exp = true;
        validation.validate_nbf = true; // vuln-0019 修复：拒绝 nbf 为未来的 token
                                        // leeway=0：不容忍时钟偏差，过期立即拒绝（安全框架默认严格）
        validation.leeway = 0;
        decode::<BulwarkJwtClaims>(token, &key, &validation)
            .map(|data| data.claims)
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("ExpiredSignature") {
                    BulwarkError::ExpiredToken(format!("JWT 已过期: {}", e))
                } else if msg.contains("ImmatureSignature") || msg.contains("nbf") {
                    // vuln-0019 修复：nbf 为未来时间 → ImmatureSignature
                    BulwarkError::InvalidToken(format!("JWT 未生效（nbf 校验失败）: {}", e))
                } else {
                    BulwarkError::InvalidToken(format!("JWT 校验失败: {}", e))
                }
            })
    }

    /// 刷新 JWT：解析旧 token 的 claims → 签发新 token。
    ///
    /// # 参数
    /// - `token`: 旧 JWT 字符串（需可成功 verify）。
    /// - `new_timeout`: 新 token 的有效期（秒）。
    ///
    /// # 返回
    /// - `Ok(String)`: 新 JWT 字符串。
    /// - `Err(BulwarkError)`: 旧 token 校验失败或新 token 签发失败。
    pub fn refresh(&self, token: &str, new_timeout: i64) -> BulwarkResult<String> {
        let claims = self.verify(token)?;
        self.sign(claims.login_id, new_timeout)
    }
}

#[cfg(feature = "protocol-zeroize")]
impl Drop for JwtHandler {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}
