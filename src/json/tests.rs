// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! json 模块测试（从 mod.rs 迁移）。

use super::*;
use crate::error::GarrisonError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// GarrisonJsonTemplate 测试

#[test]
fn new_parses_valid_json() {
    let template = GarrisonJsonTemplate::new(r#"{"code":0,"msg":"${msg}"}"#);
    assert!(template.is_ok());
    let t = template.unwrap();
    assert!(t.value().is_object());
}

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

#[test]
fn render_preserves_unprovided_placeholders() {
    let template = GarrisonJsonTemplate::new(r#"{"msg":"${missing}"}"#).unwrap();
    let params = HashMap::new();
    let rendered = template.render(&params).unwrap();
    assert!(rendered.contains("${missing}"));
}

#[test]
fn render_outputs_valid_json() {
    let template = GarrisonJsonTemplate::new(r#"{"code":0,"msg":"${msg}"}"#).unwrap();
    let mut params = HashMap::new();
    params.insert("msg".to_string(), "ok".to_string());
    let rendered = template.render(&params).unwrap();
    let reparsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(reparsed["code"], 0);
    assert_eq!(reparsed["msg"], "ok");
}

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

#[test]
fn render_replaces_multiple_occurrences() {
    let template = GarrisonJsonTemplate::new(r#"{"a":"${token}","b":"${token}"}"#).unwrap();
    let mut params = HashMap::new();
    params.insert("token".to_string(), "T".to_string());
    let rendered = template.render(&params).unwrap();
    assert_eq!(rendered.matches("\"T\"").count(), 2);
}

#[test]
fn json_template_clone_preserves_value() {
    let template = GarrisonJsonTemplate::new(r#"{"key":"value"}"#).unwrap();
    let cloned = template.clone();
    assert_eq!(template.value(), cloned.value());
}

// GarrisonSerializer / GarrisonSerializerDefault 测试

/// 测试用的序列化类型。
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct TestData {
    name: String,
    age: u32,
}

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

#[test]
fn serializer_default_deserialize_from_json() {
    let serializer = GarrisonSerializerDefault;
    let json = r#"{"name":"bob","age":25}"#;
    let data: TestData = serializer.deserialize(json).unwrap();
    assert_eq!(data.name, "bob");
    assert_eq!(data.age, 25);
}

#[test]
fn serializer_default_deserialize_invalid_json_errors() {
    let serializer = GarrisonSerializerDefault;
    let result: GarrisonResult<TestData> = serializer.deserialize("not json");
    assert!(result.is_err());
}

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

#[test]
fn serializer_default_implements_default() {
    let _serializer: GarrisonSerializerDefault = Default::default();
}
