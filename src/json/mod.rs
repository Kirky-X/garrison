//! JSON 模块，提供 JSON 模板与序列化抽象。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 JSON 模板层，
//! 隔离具体 JSON 库（serde_json / simd-json 等）。
//!
//! ## 0.2.0 变更
//!
//! - `BulwarkJsonTemplate` 从 0.1.0 的占位 trait 转为具体 struct（持有 `serde_json::Value`）
//! - `BulwarkSerializerTemplate` 重命名为 `BulwarkSerializer`，方法签名保持兼容
//! - 新增 `BulwarkSerializerDefault` 默认实现（委托 serde_json）

use crate::error::{BulwarkError, BulwarkResult};
use std::collections::HashMap;

/// JSON 模板 struct，持有解析后的 `serde_json::Value`，支持 `${key}` 占位符替换。
///
/// 用于"返回统一格式的登录响应"等场景（如 `{code: 0, msg: "ok", data: "${token}"}`）。
///
/// # 示例
///
/// ```
/// use bulwark::json::BulwarkJsonTemplate;
/// use std::collections::HashMap;
///
/// let template = BulwarkJsonTemplate::new(r#"{"code":0,"msg":"${msg}"}"#).unwrap();
/// let mut params = HashMap::new();
/// params.insert("msg".to_string(), "ok".to_string());
/// let rendered = template.render(&params).unwrap();
/// assert!(rendered.contains("\"ok\""));
/// ```
#[derive(Debug, Clone)]
pub struct BulwarkJsonTemplate {
    /// 解析后的 JSON Value（不保留原始字符串，避免重复解析）。
    value: serde_json::Value,
}

impl BulwarkJsonTemplate {
    /// 解析 JSON 字符串为模板（依据 spec json-template Requirement: 模板构造与渲染）。
    ///
    /// # 参数
    /// - `template`: JSON 字符串，可包含 `${key}` 占位符。
    ///
    /// # 返回
    /// - `Ok(Self)`: 解析成功，struct 内部持有解析后的 `Value`。
    /// - `Err(BulwarkError::Internal)`: JSON 解析失败，消息含解析错误信息。
    pub fn new(template: &str) -> BulwarkResult<Self> {
        let value: serde_json::Value = serde_json::from_str(template)
            .map_err(|e| BulwarkError::Internal(format!("JSON 模板解析失败: {}", e)))?;
        Ok(Self { value })
    }

    /// 递归替换 `${key}` 占位符并序列化为 JSON 字符串（依据 spec json-template Requirement: 模板构造与渲染）。
    ///
    /// # 参数
    /// - `params`: 占位符键值对。未在 `params` 中提供的 `${key}` 保留原样。
    ///
    /// # 返回
    /// - `Ok(String)`: 渲染后的 JSON 字符串（可被 `serde_json::from_str` 再次解析）。
    /// - `Err(BulwarkError::Internal)`: 序列化失败。
    pub fn render(&self, params: &HashMap<String, String>) -> BulwarkResult<String> {
        let rendered = render_value(self.value.clone(), params);
        serde_json::to_string(&rendered)
            .map_err(|e| BulwarkError::Internal(format!("JSON 序列化失败: {}", e)))
    }

    /// 获取内部 `Value` 的引用（便于直接访问）。
    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }
}

/// 递归替换 `Value` 中的 `${key}` 占位符。
///
/// - `String` 类型: 执行占位符替换
/// - `Object` 类型: 递归处理每个值
/// - `Array` 类型: 递归处理每个元素
/// - 其他类型: 原样返回
fn render_value(
    mut value: serde_json::Value,
    params: &HashMap<String, String>,
) -> serde_json::Value {
    match &mut value {
        serde_json::Value::String(s) => {
            for (key, val) in params {
                let placeholder = format!("${{{}}}", key);
                if s.contains(&placeholder) {
                    *s = s.replace(&placeholder, val);
                }
            }
            value
        },
        serde_json::Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                *v = render_value(v.clone(), params);
            }
            value
        },
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                *v = render_value(v.clone(), params);
            }
            value
        },
        _ => value,
    }
}

/// 序列化抽象 trait，提供类型化的序列化/反序列化（依据 spec json-template Requirement: BulwarkSerializer trait 定义）。
///
/// [借鉴 Sa-Token] 对应 `SaSerializerTemplate`，0.1.0 的 `BulwarkSerializerTemplate` 重命名为此。
pub trait BulwarkSerializer {
    /// 将类型化对象序列化为 JSON 字符串。
    ///
    /// # 类型参数
    /// - `T`: 序列化对象类型，需实现 `serde::Serialize`。
    fn serialize<T: serde::Serialize>(&self, value: &T) -> BulwarkResult<String>;

    /// 将 JSON 字符串反序列化为类型化对象。
    ///
    /// # 类型参数
    /// - `T`: 反序列化目标类型，需实现 `serde::de::DeserializeOwned`。
    fn deserialize<T: serde::de::DeserializeOwned>(&self, json: &str) -> BulwarkResult<T>;
}

/// `BulwarkSerializer` 的默认实现，委托 `serde_json`（依据 spec json-template Requirement: 默认实现委托 serde_json）。
///
/// 业务方可透明切换底层 JSON 库（如 simd-json）通过实现 `BulwarkSerializer` trait。
#[derive(Debug, Clone, Default)]
pub struct BulwarkSerializerDefault;

impl BulwarkSerializer for BulwarkSerializerDefault {
    fn serialize<T: serde::Serialize>(&self, value: &T) -> BulwarkResult<String> {
        serde_json::to_string(value)
            .map_err(|e| BulwarkError::Internal(format!("JSON 序列化失败: {}", e)))
    }

    fn deserialize<T: serde::de::DeserializeOwned>(&self, json: &str) -> BulwarkResult<T> {
        serde_json::from_str(json)
            .map_err(|e| BulwarkError::Internal(format!("JSON 反序列化失败: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    // ========================================================================
    // BulwarkJsonTemplate 测试（依据 spec json-template）
    // ========================================================================

    /// 验证 `new` 成功解析合法 JSON（依据 spec Scenario: new 成功解析合法 JSON）。
    #[test]
    fn new_parses_valid_json() {
        let template = BulwarkJsonTemplate::new(r#"{"code":0,"msg":"${msg}"}"#);
        assert!(template.is_ok());
        let t = template.unwrap();
        assert!(t.value().is_object());
    }

    /// 验证 `new` 解析非法 JSON 抛错（依据 spec Scenario: new 解析非法 JSON 抛错）。
    #[test]
    fn new_rejects_invalid_json() {
        let result = BulwarkJsonTemplate::new("not a json");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, BulwarkError::Internal(ref msg) if msg.contains("JSON 模板解析失败")),
            "应返回 Internal 错误含 'JSON 模板解析失败'，实际: {:?}",
            err
        );
    }

    /// 验证 `render` 递归替换嵌套对象占位符（依据 spec Scenario: render 递归替换嵌套对象占位符）。
    #[test]
    fn render_replaces_nested_placeholders() {
        let template =
            BulwarkJsonTemplate::new(r#"{"data":{"token":"${token}","user":"${user}"}}"#).unwrap();
        let mut params = HashMap::new();
        params.insert("token".to_string(), "T1".to_string());
        params.insert("user".to_string(), "alice".to_string());
        let rendered = template.render(&params).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["data"]["token"], "T1");
        assert_eq!(parsed["data"]["user"], "alice");
    }

    /// 验证 `render` 未提供的占位符保留原样。
    #[test]
    fn render_preserves_unprovided_placeholders() {
        let template = BulwarkJsonTemplate::new(r#"{"msg":"${missing}"}"#).unwrap();
        let params = HashMap::new();
        let rendered = template.render(&params).unwrap();
        // 未提供的 ${missing} 保留原样
        assert!(rendered.contains("${missing}"));
    }

    /// 验证 `render` 输出合法 JSON 字符串（依据 spec Scenario: render 输出合法 JSON 字符串）。
    #[test]
    fn render_outputs_valid_json() {
        let template = BulwarkJsonTemplate::new(r#"{"code":0,"msg":"${msg}"}"#).unwrap();
        let mut params = HashMap::new();
        params.insert("msg".to_string(), "ok".to_string());
        let rendered = template.render(&params).unwrap();
        // 可被 serde_json::from_str 再次解析
        let reparsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(reparsed["code"], 0);
        assert_eq!(reparsed["msg"], "ok");
    }

    /// 验证 `render` 处理数组中的占位符。
    #[test]
    fn render_replaces_placeholders_in_array() {
        let template = BulwarkJsonTemplate::new(r#"{"items":["${a}","${b}"]}"#).unwrap();
        let mut params = HashMap::new();
        params.insert("a".to_string(), "x".to_string());
        params.insert("b".to_string(), "y".to_string());
        let rendered = template.render(&params).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["items"][0], "x");
        assert_eq!(parsed["items"][1], "y");
    }

    /// 验证 `render` 同一占位符多次出现全部替换。
    #[test]
    fn render_replaces_multiple_occurrences() {
        let template = BulwarkJsonTemplate::new(r#"{"a":"${token}","b":"${token}"}"#).unwrap();
        let mut params = HashMap::new();
        params.insert("token".to_string(), "T".to_string());
        let rendered = template.render(&params).unwrap();
        assert_eq!(rendered.matches("\"T\"").count(), 2);
    }

    /// 验证 `BulwarkJsonTemplate` 派生 `Clone`。
    #[test]
    fn json_template_clone_preserves_value() {
        let template = BulwarkJsonTemplate::new(r#"{"key":"value"}"#).unwrap();
        let cloned = template.clone();
        assert_eq!(template.value(), cloned.value());
    }

    // ========================================================================
    // BulwarkSerializer / BulwarkSerializerDefault 测试（依据 spec json-template）
    // ========================================================================

    /// 测试用的序列化类型。
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct TestData {
        name: String,
        age: u32,
    }

    /// 验证 `BulwarkSerializerDefault::serialize` 将对象转为 JSON 字符串（依据 spec Scenario: 默认实现委托 serde_json 序列化）。
    #[test]
    fn serializer_default_serialize_to_json() {
        let serializer = BulwarkSerializerDefault;
        let data = TestData {
            name: "alice".to_string(),
            age: 30,
        };
        let json = serializer.serialize(&data).unwrap();
        assert!(json.contains("alice"));
        assert!(json.contains("30"));
    }

    /// 验证 `BulwarkSerializerDefault::deserialize` 将 JSON 字符串转为对象（依据 spec Scenario: 默认实现委托 serde_json 反序列化）。
    #[test]
    fn serializer_default_deserialize_from_json() {
        let serializer = BulwarkSerializerDefault;
        let json = r#"{"name":"bob","age":25}"#;
        let data: TestData = serializer.deserialize(json).unwrap();
        assert_eq!(data.name, "bob");
        assert_eq!(data.age, 25);
    }

    /// 验证 `deserialize` 非法 JSON 抛错（依据 spec Scenario: deserialize 非法 JSON 抛错）。
    #[test]
    fn serializer_default_deserialize_invalid_json_errors() {
        let serializer = BulwarkSerializerDefault;
        let result: BulwarkResult<TestData> = serializer.deserialize("not json");
        assert!(result.is_err());
    }

    /// 验证 `serialize` / `deserialize` 往返一致。
    #[test]
    fn serializer_default_roundtrip() {
        let serializer = BulwarkSerializerDefault;
        let original = TestData {
            name: "charlie".to_string(),
            age: 40,
        };
        let json = serializer.serialize(&original).unwrap();
        let deserialized: TestData = serializer.deserialize(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    /// 验证 `BulwarkSerializerDefault` 派生 `Default`。
    #[test]
    fn serializer_default_implements_default() {
        let _serializer: BulwarkSerializerDefault = Default::default();
    }
}
