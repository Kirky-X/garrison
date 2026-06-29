//! JSON 模块，提供 JSON 模板与序列化抽象。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 JSON 模板层，
//! 隔离具体 JSON 库（serde_json / simd-json 等）。

use crate::error::BulwarkResult;

/// JSON 模板 trait，提供 JSON 字符串与对象互转抽象。
///
/// [借鉴 Sa-Token] 对应 `SaJsonTemplate`。
pub trait BulwarkJsonTemplate {
    /// 将对象序列化为 JSON 字符串。
    ///
    /// # 参数
    /// - `value`: 待序列化对象。
    fn to_json_string(&self, value: &serde_json::Value) -> BulwarkResult<String> {
        todo!()
    }

    /// 将 JSON 字符串反序列化为对象。
    ///
    /// # 参数
    /// - `json`: JSON 字符串。
    fn parse_json(&self, json: &str) -> BulwarkResult<serde_json::Value> {
        todo!()
    }
}

/// 序列化模板 trait，提供类型化序列化 / 反序列化抽象。
///
/// [借鉴 Sa-Token] 对应 `SaSerializerTemplate`，
/// 支持泛型类型安全转换。
pub trait BulwarkSerializerTemplate {
    /// 将类型化对象序列化为 JSON 字符串。
    ///
    /// # 类型参数
    /// - `T`: 序列化对象类型，需实现 `serde::Serialize`。
    ///
    /// # 参数
    /// - `value`: 待序列化对象。
    fn serialize<T: serde::Serialize>(&self, value: &T) -> BulwarkResult<String> {
        todo!()
    }

    /// 将 JSON 字符串反序列化为类型化对象。
    ///
    /// # 类型参数
    /// - `T`: 反序列化目标类型，需实现 `serde::de::DeserializeOwned`。
    ///
    /// # 参数
    /// - `json`: JSON 字符串。
    fn deserialize<T: serde::de::DeserializeOwned>(&self, json: &str) -> BulwarkResult<T> {
        todo!()
    }
}
