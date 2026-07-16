//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `BulwarkJsonTemplate` 实现：JSON 模板解析与 `${key}` 占位符替换。

use crate::error::{BulwarkError, BulwarkResult};
use crate::json::BulwarkJsonTemplate;
use std::collections::HashMap;

impl BulwarkJsonTemplate {
    /// 解析 JSON 字符串为模板。
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

    /// 递归替换 `${key}` 占位符并序列化为 JSON 字符串。
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
