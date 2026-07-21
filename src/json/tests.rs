//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! json 模块测试（从 mod.rs 迁移，Rule 25 合规）。

use super::*;
use crate::error::GarrisonError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ========================================================================
// GarrisonJsonTemplate 测试
// ========================================================================

/// 验证 `new` 成功解析合法 JSON。
#[test]
fn new_parses_valid_json() {
    let template = GarrisonJsonTemplate::new(r#"{"code":0,"msg":"${msg}"}"#);
    assert!(template.is_ok());
    let t = template.unwrap();
    assert!(t.value().is_object());
}

/// 验证 `new` 解析非法 JSON 抛错。
#[test]
fn new_rejects_invalid_json() {
    let result = GarrisonJsonTemplate::new("not a json");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, GarrisonError::Internal(ref msg) if msg.contains("json-template-parse")),
        "应返回 Internal 错误含 json-template-parse，实际: {:?}",
        err
    );
}

/// 验证 `render` 递归替换嵌套对象占位符。
#[test]
fn render_replaces_nested_placeholders() {
    let template =
        GarrisonJsonTemplate::new(r#"{"data":{"token":"${token}","user":"${user}"}}"#).unwrap();
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
    let template = GarrisonJsonTemplate::new(r#"{"msg":"${missing}"}"#).unwrap();
    let params = HashMap::new();
    let rendered = template.render(&params).unwrap();
    // 未提供的 ${missing} 保留原样
    assert!(rendered.contains("${missing}"));
}

/// 验证 `render` 输出合法 JSON 字符串。
#[test]
fn render_outputs_valid_json() {
    let template = GarrisonJsonTemplate::new(r#"{"code":0,"msg":"${msg}"}"#).unwrap();
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
    let template = GarrisonJsonTemplate::new(r#"{"items":["${a}","${b}"]}"#).unwrap();
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
    let template = GarrisonJsonTemplate::new(r#"{"a":"${token}","b":"${token}"}"#).unwrap();
    let mut params = HashMap::new();
    params.insert("token".to_string(), "T".to_string());
    let rendered = template.render(&params).unwrap();
    assert_eq!(rendered.matches("\"T\"").count(), 2);
}

/// 验证 `GarrisonJsonTemplate` 派生 `Clone`。
#[test]
fn json_template_clone_preserves_value() {
    let template = GarrisonJsonTemplate::new(r#"{"key":"value"}"#).unwrap();
    let cloned = template.clone();
    assert_eq!(template.value(), cloned.value());
}

// ========================================================================
// GarrisonSerializer / GarrisonSerializerDefault 测试
// ========================================================================

/// 测试用的序列化类型。
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct TestData {
    name: String,
    age: u32,
}

/// 验证 `GarrisonSerializerDefault::serialize` 将对象转为 JSON 字符串。
#[test]
fn serializer_default_serialize_to_json() {
    let serializer = GarrisonSerializerDefault;
    let data = TestData {
        name: "alice".to_string(),
        age: 30,
    };
    let json = serializer.serialize(&data).unwrap();
    assert!(json.contains("alice"));
    assert!(json.contains("30"));
}

/// 验证 `GarrisonSerializerDefault::deserialize` 将 JSON 字符串转为对象。
#[test]
fn serializer_default_deserialize_from_json() {
    let serializer = GarrisonSerializerDefault;
    let json = r#"{"name":"bob","age":25}"#;
    let data: TestData = serializer.deserialize(json).unwrap();
    assert_eq!(data.name, "bob");
    assert_eq!(data.age, 25);
}

/// 验证 `deserialize` 非法 JSON 抛错。
#[test]
fn serializer_default_deserialize_invalid_json_errors() {
    let serializer = GarrisonSerializerDefault;
    let result: GarrisonResult<TestData> = serializer.deserialize("not json");
    assert!(result.is_err());
}

/// 验证 `serialize` / `deserialize` 往返一致。
#[test]
fn serializer_default_roundtrip() {
    let serializer = GarrisonSerializerDefault;
    let original = TestData {
        name: "charlie".to_string(),
        age: 40,
    };
    let json = serializer.serialize(&original).unwrap();
    let deserialized: TestData = serializer.deserialize(&json).unwrap();
    assert_eq!(original, deserialized);
}

/// 验证 `GarrisonSerializerDefault` 派生 `Default`。
#[test]
fn serializer_default_implements_default() {
    let _serializer: GarrisonSerializerDefault = Default::default();
}
