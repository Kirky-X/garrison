//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Token 抽象模块，定义 Token 生成/验证/解析的 trait 与多种风格实现。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 Token 风格切换能力，
//! 0.2.0 将 token 逻辑独立为 `core-token` 模块，
//! 框架内部通过 `Token` trait 实现多种 token 风格切换。
//!
//! 支持 4 种风格：uuid / random_64 / simple / jwt。

use crate::error::{BulwarkError, BulwarkResult};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// 64 字符随机 hex 风格 Token。
///
/// 生成 64 字符随机十六进制串，多次调用返回不同 token。
/// 不包含 login_id 或过期信息，`verify` 始终返回 `Ok(None)`。
#[derive(Debug, Clone, Copy, Default)]
pub struct Random64TokenStyle;

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

/// Simple 风格 Token。
///
/// 格式为 `<login_id>-<uuid>`，可通过前缀解析 login_id。
#[derive(Debug, Clone, Copy, Default)]
pub struct SimpleTokenStyle;

impl Token for SimpleTokenStyle {
    fn generate(&self, login_id: &str, _timeout: i64) -> BulwarkResult<String> {
        Ok(format!("{}-{}", login_id, Uuid::new_v4()))
    }

    fn verify(&self, token: &str) -> BulwarkResult<Option<String>> {
        match token.split_once('-') {
            Some((id_str, _)) => Ok(Some(id_str.to_string())),
            None => Ok(None),
        }
    }

    fn parse(&self, token: &str) -> BulwarkResult<TokenClaims> {
        match token.split_once('-') {
            Some((id_str, _)) => {
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

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // TokenClaims 测试
    // ========================================================================

    /// TokenClaims 可序列化/反序列化。
    #[test]
    fn token_claims_serializes() {
        let claims = TokenClaims {
            login_id: "1001".to_string(),
            expire_at: 1700003600,
            device: Some("web".to_string()),
        };
        let json = serde_json::to_string(&claims).unwrap();
        let parsed: TokenClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.login_id, "1001");
        assert_eq!(parsed.expire_at, 1700003600);
        assert_eq!(parsed.device, Some("web".to_string()));
    }

    /// TokenClaims device 字段可选。
    #[test]
    fn token_claims_device_optional() {
        let claims = TokenClaims {
            login_id: "1".to_string(),
            expire_at: 0,
            device: None,
        };
        assert!(claims.device.is_none());
    }

    // ========================================================================
    // UuidTokenStyle 测试
    // ========================================================================

    /// UuidTokenStyle 生成 UUID v4 格式 token。
    #[test]
    fn uuid_style_generates_uuid_format() {
        let style = UuidTokenStyle;
        let token = style.generate("1001", 3600).unwrap();
        // UUID v4 格式：8-4-4-4-12 十六进制
        assert_eq!(token.len(), 36);
        let parts: Vec<&str> = token.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
    }

    /// UuidTokenStyle verify 始终返回 None。
    #[test]
    fn uuid_style_verify_returns_none() {
        let style = UuidTokenStyle;
        let token = style.generate("1001", 3600).unwrap();
        assert_eq!(style.verify(&token).unwrap(), None);
    }

    /// UuidTokenStyle parse 返回错误。
    #[test]
    fn uuid_style_parse_errors() {
        let style = UuidTokenStyle;
        assert!(style.parse("some-token").is_err());
    }

    // ========================================================================
    // Random64TokenStyle 测试
    // ========================================================================

    /// Random64TokenStyle 生成 64 字符随机 hex。
    #[test]
    fn random64_style_generates_64_hex() {
        let style = Random64TokenStyle;
        let token = style.generate("1001", 3600).unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Random64TokenStyle 多次调用返回不同 token。
    #[test]
    fn random64_style_generates_unique() {
        let style = Random64TokenStyle;
        let t1 = style.generate("1001", 3600).unwrap();
        let t2 = style.generate("1001", 3600).unwrap();
        assert_ne!(t1, t2);
    }

    /// Random64TokenStyle verify 始终返回 None。
    #[test]
    fn random64_style_verify_returns_none() {
        let style = Random64TokenStyle;
        assert_eq!(style.verify("abc123").unwrap(), None);
    }

    // ========================================================================
    // SimpleTokenStyle 测试
    // ========================================================================

    /// SimpleTokenStyle 生成 `<login_id>-<uuid>` 格式。
    #[test]
    fn simple_style_generates_login_id_prefix() {
        let style = SimpleTokenStyle;
        let token = style.generate("1001", 3600).unwrap();
        assert!(token.starts_with("1001-"));
        // 后缀为 UUID v4 格式（36 字符）
        let uuid_part = &token[5..]; // 跳过 "1001-"
        assert_eq!(uuid_part.len(), 36);
    }

    /// SimpleTokenStyle verify 解析 login_id。
    #[test]
    fn simple_style_verify_extracts_login_id() {
        let style = SimpleTokenStyle;
        let token = style.generate("2002", 3600).unwrap();
        let login_id = style.verify(&token).unwrap();
        assert_eq!(login_id, Some("2002".to_string()));
    }

    /// SimpleTokenStyle parse 返回 TokenClaims。
    #[test]
    fn simple_style_parse_returns_claims() {
        let style = SimpleTokenStyle;
        let token = style.generate("3003", 3600).unwrap();
        let claims = style.parse(&token).unwrap();
        assert_eq!(claims.login_id, "3003");
    }

    /// SimpleTokenStyle parse 非数字 login_id 返回 Ok（String 类型不再要求数字）。
    #[test]
    fn simple_style_parse_non_numeric_login_id_returns_ok() {
        let style = SimpleTokenStyle;
        // "no-dash-here" split_once('-') => Some(("no", "dash-here"))
        // String 类型 login_id 接受任意字符串
        let result = style.parse("no-dash-here");
        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.login_id, "no");
    }

    /// SimpleTokenStyle parse 无分隔符返回 Err。
    #[test]
    fn simple_style_parse_no_separator_errors() {
        let style = SimpleTokenStyle;
        assert!(style.parse("noseparator").is_err());
    }

    // ========================================================================
    // TokenStyleFactory 测试
    // ========================================================================

    /// Factory 返回 UuidTokenStyle。
    #[test]
    fn factory_creates_uuid_style() {
        let token = TokenStyleFactory::new("uuid", "secret").unwrap();
        let t = token.generate("1", 60).unwrap();
        assert_eq!(t.len(), 36);
    }

    /// Factory 返回 Random64TokenStyle。
    #[test]
    fn factory_creates_random64_style() {
        let token = TokenStyleFactory::new("random_64", "secret").unwrap();
        let t = token.generate("1", 60).unwrap();
        assert_eq!(t.len(), 64);
    }

    /// Factory 返回 SimpleTokenStyle。
    #[test]
    fn factory_creates_simple_style() {
        let token = TokenStyleFactory::new("simple", "secret").unwrap();
        let t = token.generate("42", 60).unwrap();
        assert!(t.starts_with("42-"));
    }

    /// Factory 未知风格返回 Config 错误（spec Scenario）。
    #[test]
    fn factory_rejects_unknown_style() {
        let result = TokenStyleFactory::new("unknown", "secret");
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::Config(msg)) => assert!(msg.contains("unknown token_style")),
            other => panic!("期望 Config 错误，实际: {:?}", other),
        }
    }

    /// Factory jwt 风格在无 protocol-jwt feature 时返回错误。
    #[cfg(not(feature = "protocol-jwt"))]
    #[test]
    fn factory_jwt_without_feature_errors() {
        let result = TokenStyleFactory::new("jwt", "secret");
        assert!(result.is_err());
    }

    /// Factory jwt 风格在有 protocol-jwt feature 时成功创建。
    #[cfg(feature = "protocol-jwt")]
    #[test]
    fn factory_creates_jwt_style() {
        let token = TokenStyleFactory::new("jwt", "secret");
        assert!(token.is_ok());
    }

    // ========================================================================
    // 覆盖率补充测试（Random64TokenStyle::parse / SimpleTokenStyle::verify 边界）
    // ========================================================================

    /// Random64TokenStyle::parse 返回 Err（无 payload）。
    #[test]
    fn random64_style_parse_errors() {
        let style = Random64TokenStyle;
        let result = style.parse("any-token");
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::Internal(msg)) => {
                assert!(msg.contains("random_64"), "应提示 random_64 不支持 parse")
            },
            other => panic!("期望 Internal 错误，实际: {:?}", other),
        }
    }

    /// SimpleTokenStyle::verify 无分隔符时返回 Ok(None)（spec: token 不含 login_id）。
    #[test]
    fn simple_style_verify_no_separator_returns_none() {
        let style = SimpleTokenStyle;
        let result = style.verify("noseparator").unwrap();
        assert_eq!(result, None, "无 '-' 分隔符的 token verify 应返回 None");
    }

    /// SimpleTokenStyle::verify 非数字 login_id 返回 Ok（String 类型不再要求数字）。
    #[test]
    fn simple_style_verify_non_numeric_returns_ok() {
        let style = SimpleTokenStyle;
        // "abc-xyz" 中 "abc" 作为 String login_id 合法
        let result = style.verify("abc-xyz");
        assert!(result.is_ok(), "verify 应返回 Ok，实际: {:?}", result);
        assert_eq!(result.unwrap(), Some("abc".to_string()));
    }

    // ========================================================================
    // JwtTokenStyle 覆盖率补充测试（feature-gated）
    // ========================================================================

    /// JwtTokenStyle generate + verify 往返测试。
    #[cfg(feature = "protocol-jwt")]
    #[test]
    fn jwt_style_generate_and_verify_roundtrip() {
        let style = JwtTokenStyle::new("test-secret-key");
        let token = style.generate("1001", 3600).unwrap();
        let login_id = style.verify(&token).unwrap();
        assert_eq!(
            login_id,
            Some("1001".to_string()),
            "JWT verify 应返回 generate 时的 login_id"
        );
    }

    /// JwtTokenStyle::verify 无效 token 返回 Ok(None)。
    #[cfg(feature = "protocol-jwt")]
    #[test]
    fn jwt_style_verify_invalid_returns_none() {
        let style = JwtTokenStyle::new("test-secret-key");
        // 篡改的 token（无法通过签名校验）
        let result = style.verify("invalid.jwt.token").unwrap();
        assert_eq!(result, None, "无效 JWT verify 应返回 Ok(None)");
    }

    /// JwtTokenStyle::parse 有效 token 返回 TokenClaims。
    #[cfg(feature = "protocol-jwt")]
    #[test]
    fn jwt_style_parse_valid_returns_claims() {
        let style = JwtTokenStyle::new("test-secret-key");
        let token = style.generate("2002", 3600).unwrap();
        let claims = style.parse(&token).unwrap();
        assert_eq!(claims.login_id, "2002");
        assert!(claims.expire_at > 0, "JWT parse 应返回非零过期时间");
    }

    /// JwtTokenStyle::parse 无效 token 返回 Err。
    #[cfg(feature = "protocol-jwt")]
    #[test]
    fn jwt_style_parse_invalid_returns_error() {
        let style = JwtTokenStyle::new("test-secret-key");
        let result = style.parse("invalid.jwt.token");
        assert!(result.is_err(), "无效 JWT parse 应返回 Err");
    }
}
