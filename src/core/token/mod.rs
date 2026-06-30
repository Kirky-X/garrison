//! Token 模型模块，定义 Token 数据结构。
//!
//! [借鉴 Sa-Token] Token 信息模型，对应 Sa-Token 的 `SaTokenInfo` / `TokenSign` 数据结构。
//!
//! 该模块在 0.1.0 为占位实现，完整功能将在 0.2.0+ 提供。

use serde::{Deserialize, Serialize};

/// Token 数据结构，表示一个认证令牌。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Token 字符串值。
    pub value: String,

    /// 关联的登录主体标识。
    pub login_id: i64,

    /// 创建时间戳（Unix 秒）。
    pub created_at: i64,

    /// 过期时间戳（Unix 秒）。
    pub expires_at: i64,
}

impl Token {
    /// 创建新的 Token 实例。
    ///
    /// # 参数
    /// - `value`: Token 字符串值。
    /// - `login_id`: 登录主体标识。
    pub fn new(_value: impl Into<String>, _login_id: i64) -> Self {
        todo!()
    }

    /// 检查 Token 是否已过期。
    pub fn is_expired(&self) -> bool {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 `Token::new` 在 0.2.0+ 实现前调用必 panic。
    /// Rust `todo!()` panic 消息为 "not yet implemented: ..."。
    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn token_new_panics_with_todo() {
        let _ = Token::new("some-token", 1001);
    }

    /// 验证 `Token::is_expired` 在 0.2.0+ 实现前调用必 panic。
    ///
    /// 通过反序列化构造一个 Token 实例（绕过 `new` 的 todo!()），
    /// 然后调用 `is_expired` 验证其 panic。
    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn token_is_expired_panics_with_todo() {
        // 通过反序列化构造 Token（避开 new 的 todo!()）
        let json = r#"{"value":"abc","login_id":1,"created_at":0,"expires_at":0}"#;
        let token: Token = serde_json::from_str(json).unwrap();
        let _ = token.is_expired();
    }

    /// 验证 `Token` 结构体可序列化为 JSON。
    #[test]
    fn token_serializes_to_json() {
        let json = r#"{"value":"abc","login_id":1,"created_at":0,"expires_at":0}"#;
        let token: Token = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&token).unwrap();
        assert!(serialized.contains("\"value\":\"abc\""));
        assert!(serialized.contains("\"login_id\":1"));
    }

    /// 验证 `Token` 结构体实现了 Debug 与 Clone。
    #[test]
    fn token_implements_debug_and_clone() {
        let json = r#"{"value":"abc","login_id":1,"created_at":0,"expires_at":0}"#;
        let token: Token = serde_json::from_str(json).unwrap();
        let cloned = token.clone();
        assert_eq!(token.value, cloned.value);
        // 验证 Debug 实现可格式化
        let _debug_str = format!("{:?}", token);
    }
}
