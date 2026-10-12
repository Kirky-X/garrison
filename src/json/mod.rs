// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! JSON 模块，对应上游 JSON 模板层，隔离具体 JSON 库（serde_json / simd-json 等）。
//!
//! 组成：`GarrisonJsonTemplate` struct（持有 `serde_json::Value`）、`GarrisonSerializer` trait（方法签名稳定）、`GarrisonSerializerDefault`（委托 serde_json）。

pub mod serializer;
pub mod template;

use crate::error::GarrisonResult;

/// JSON 模板 struct，持有解析后的 `serde_json::Value`，支持 `${key}` 占位符替换。
///
/// 用于"返回统一格式的登录响应"等场景（如 `{code: 0, msg: "ok", data: "${token}"}`）。
///
/// # 示例
///
/// ```
/// use garrison::json::GarrisonJsonTemplate;
/// use std::collections::HashMap;
///
/// let template = GarrisonJsonTemplate::new(r#"{"code":0,"msg":"${msg}"}"#).unwrap();
/// let mut params = HashMap::new();
/// params.insert("msg".to_string(), "ok".to_string());
/// let rendered = template.render(&params).unwrap();
/// assert!(rendered.contains("\"ok\""));
/// ```
#[derive(Debug, Clone)]
pub struct GarrisonJsonTemplate {
    /// 解析后的 JSON Value（不保留原始字符串，避免重复解析）。
    value: serde_json::Value,
}

/// 序列化抽象 trait（对应 `SaSerializerTemplate`），提供类型化的序列化/反序列化。
pub trait GarrisonSerializer {
    /// 将类型化对象序列化为 JSON 字符串。
    fn serialize<T: serde::Serialize>(&self, value: &T) -> GarrisonResult<String>;

    /// 将 JSON 字符串反序列化为类型化对象。
    fn deserialize<T: serde::de::DeserializeOwned>(&self, json: &str) -> GarrisonResult<T>;
}

/// `GarrisonSerializer` 默认实现，委托 `serde_json`；业务方可实现 trait 透明切换底层库（如 simd-json）。
#[derive(Debug, Clone, Default)]
pub struct GarrisonSerializerDefault;

#[cfg(test)]
mod tests;
