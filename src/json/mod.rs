//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! JSON 模块，提供 JSON 模板与序列化抽象。
//!
//! 对应 JSON 模板层，
//! 隔离具体 JSON 库（serde_json / simd-json 等）。
//!
//! ## 0.2.0 变更
//!
//! - `GarrisonJsonTemplate` 从 0.1.0 的占位 trait 转为具体 struct（持有 `serde_json::Value`）
//! - `GarrisonSerializerTemplate` 重命名为 `GarrisonSerializer`，方法签名保持兼容
//! - 新增 `GarrisonSerializerDefault` 默认实现（委托 serde_json）

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

/// 序列化抽象 trait，提供类型化的序列化/反序列化。
///
/// 对应 `SaSerializerTemplate`，0.1.0 的 `GarrisonSerializerTemplate` 重命名为此。
pub trait GarrisonSerializer {
    /// 将类型化对象序列化为 JSON 字符串。
    ///
    /// # 类型参数
    /// - `T`: 序列化对象类型，需实现 `serde::Serialize`。
    fn serialize<T: serde::Serialize>(&self, value: &T) -> GarrisonResult<String>;

    /// 将 JSON 字符串反序列化为类型化对象。
    ///
    /// # 类型参数
    /// - `T`: 反序列化目标类型，需实现 `serde::de::DeserializeOwned`。
    fn deserialize<T: serde::de::DeserializeOwned>(&self, json: &str) -> GarrisonResult<T>;
}

/// `GarrisonSerializer` 的默认实现，委托 `serde_json`。
///
/// 业务方可透明切换底层 JSON 库（如 simd-json）通过实现 `GarrisonSerializer` trait。
#[derive(Debug, Clone, Default)]
pub struct GarrisonSerializerDefault;

#[cfg(test)]
mod tests;
