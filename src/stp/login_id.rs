//! LoginId newtype — 支持 i64 与 String 双形式的登录主体标识。
//!
//! 依据 spec login-id-type R-001/R-002/R-003：
//! - `LoginId::Numeric(i64)` 兼容旧 `i64` 调用
//! - `LoginId::String(String)` 支持 UUID/用户名等字符串标识
//! - 所有 `login_id: i64` 签名迁移为 `login_id: impl Into<LoginId>`
//!
//! # 序列化策略
//!
//! 为了与旧 `i64` 形式的 JSON 互操作，序列化输出为字符串形式
//! （`Numeric(42)` → `"42"`，`String("abc")` → `"abc"`）。反序列化时，
//! 字符串内容若可解析为 `i64` 则还原为 `Numeric`，否则为 `String`。

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// 登录主体标识，支持数字与字符串两种形式。
///
/// # 示例
///
/// ```
/// use bulwark::stp::login_id::LoginId;
///
/// let from_num: LoginId = 42i64.into();
/// let from_str: LoginId = "user-uuid".into();
/// assert_eq!(from_num.as_str(), "42");
/// assert_eq!(from_str.as_str(), "user-uuid");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LoginId {
    /// 数字形式（兼容旧 `i64` login_id）。
    Numeric(i64),
    /// 字符串形式（UUID/用户名等）。
    String(String),
}

impl LoginId {
    /// 返回字符串形式标识。
    ///
    /// - `Numeric(42)` → `"42".to_string()`
    /// - `String("abc")` → `"abc".to_string()`
    pub fn as_str(&self) -> String {
        match self {
            LoginId::Numeric(n) => n.to_string(),
            LoginId::String(s) => s.clone(),
        }
    }

    /// 返回 `i64` 形式标识（若为 `Numeric` 变体）。
    ///
    /// - `Numeric(42)` → `Some(42)`
    /// - `String("abc")` → `None`
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            LoginId::Numeric(n) => Some(*n),
            LoginId::String(_) => None,
        }
    }
}

impl From<i64> for LoginId {
    fn from(n: i64) -> Self {
        LoginId::Numeric(n)
    }
}

impl From<String> for LoginId {
    fn from(s: String) -> Self {
        LoginId::String(s)
    }
}

impl From<&str> for LoginId {
    fn from(s: &str) -> Self {
        LoginId::String(s.to_string())
    }
}

impl fmt::Display for LoginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

// 自定义 Serialize：两个变体都序列化为字符串形式（spec R-001 要求）
impl Serialize for LoginId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_str())
    }
}

// 自定义 Deserialize：字符串内容若可解析为 i64 则 Numeric，否则 String
impl<'de> Deserialize<'de> for LoginId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if let Ok(n) = s.parse::<i64>() {
            Ok(LoginId::Numeric(n))
        } else {
            Ok(LoginId::String(s))
        }
    }
}

#[cfg(test)]
mod tests {
    // T001 Red: 测试引用尚未定义的 LoginId 类型，编译失败 = Red
    // T002 Green 将实现 LoginId enum + 所有 trait impl 使测试通过
    use super::*;

    // =========================================================================
    // R-login-id-type-001: LoginId enum 定义 + trait derive
    // =========================================================================

    #[test]
    fn from_i64_creates_numeric_variant() {
        assert_eq!(LoginId::from(42i64), LoginId::Numeric(42));
        assert_eq!(LoginId::from(0i64), LoginId::Numeric(0));
        assert_eq!(LoginId::from(-1i64), LoginId::Numeric(-1));
    }

    #[test]
    fn from_string_creates_string_variant() {
        assert_eq!(
            LoginId::from("user-uuid".to_string()),
            LoginId::String("user-uuid".to_string())
        );
    }

    #[test]
    fn from_str_creates_string_variant() {
        assert_eq!(
            LoginId::from("user-uuid"),
            LoginId::String("user-uuid".to_string())
        );
        assert_eq!(LoginId::from(""), LoginId::String("".to_string()));
    }

    #[test]
    fn debug_format_works() {
        assert_eq!(format!("{:?}", LoginId::Numeric(42)), "Numeric(42)");
        assert_eq!(
            format!("{:?}", LoginId::String("abc".to_string())),
            r#"String("abc")"#
        );
    }

    #[test]
    fn clone_works() {
        let original = LoginId::String("abc".to_string());
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn eq_and_hash_work() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn hash_of<T: Hash>(v: &T) -> u64 {
            let mut h = DefaultHasher::new();
            v.hash(&mut h);
            h.finish()
        }

        let a = LoginId::Numeric(42);
        let b = LoginId::Numeric(42);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));

        let c = LoginId::String("abc".to_string());
        let d = LoginId::String("abc".to_string());
        assert_eq!(c, d);
        assert_eq!(hash_of(&c), hash_of(&d));

        assert_ne!(a, c);
    }

    // =========================================================================
    // R-login-id-type-002: as_str / as_i64 转换
    // =========================================================================

    #[test]
    fn as_str_returns_string_form() {
        assert_eq!(LoginId::Numeric(42).as_str(), "42");
        assert_eq!(LoginId::Numeric(0).as_str(), "0");
        assert_eq!(LoginId::Numeric(-1).as_str(), "-1");
        assert_eq!(LoginId::String("abc".to_string()).as_str(), "abc");
        assert_eq!(LoginId::String("".to_string()).as_str(), "");
    }

    #[test]
    fn as_i64_returns_some_for_numeric() {
        assert_eq!(LoginId::Numeric(42).as_i64(), Some(42));
        assert_eq!(LoginId::Numeric(0).as_i64(), Some(0));
        assert_eq!(LoginId::Numeric(-1).as_i64(), Some(-1));
    }

    #[test]
    fn as_i64_returns_none_for_string_variant() {
        assert_eq!(LoginId::String("abc".to_string()).as_i64(), None);
        assert_eq!(LoginId::String("42".to_string()).as_i64(), None);
    }

    // =========================================================================
    // Display 实现
    // =========================================================================

    #[test]
    fn display_numeric_matches_as_str() {
        let id = LoginId::Numeric(42);
        assert_eq!(format!("{}", id), id.as_str());
        assert_eq!(format!("{}", id), "42");
    }

    #[test]
    fn display_string_matches_as_str() {
        let id = LoginId::String("abc".to_string());
        assert_eq!(format!("{}", id), id.as_str());
        assert_eq!(format!("{}", id), "abc");
    }

    // =========================================================================
    // Serialize / Deserialize —— 序列化为字符串形式
    // =========================================================================

    #[test]
    fn serialize_numeric_to_string_form() {
        // spec R-001: serde_json::to_string(&LoginId::Numeric(42)) 序列化为 "42"（字符串形式）
        let json = serde_json::to_string(&LoginId::Numeric(42)).expect("serialize failed");
        assert_eq!(json, "\"42\"");
    }

    #[test]
    fn serialize_string_to_string_form() {
        let json =
            serde_json::to_string(&LoginId::String("abc".to_string())).expect("serialize failed");
        assert_eq!(json, "\"abc\"");
    }

    #[test]
    fn deserialize_numeric_from_string_form() {
        let id: LoginId = serde_json::from_str("\"42\"").expect("deserialize failed");
        assert_eq!(id, LoginId::Numeric(42));
    }

    #[test]
    fn deserialize_string_from_string_form() {
        let id: LoginId = serde_json::from_str("\"abc\"").expect("deserialize failed");
        assert_eq!(id, LoginId::String("abc".to_string()));
    }

    #[test]
    fn serialize_deserialize_roundtrip_numeric() {
        let original = LoginId::Numeric(12345);
        let json = serde_json::to_string(&original).expect("serialize failed");
        let restored: LoginId = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(original, restored);
    }

    #[test]
    fn serialize_deserialize_roundtrip_string() {
        let original = LoginId::String("user-uuid-xyz".to_string());
        let json = serde_json::to_string(&original).expect("serialize failed");
        let restored: LoginId = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(original, restored);
    }
}
