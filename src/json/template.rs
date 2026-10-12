// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `GarrisonJsonTemplate` 实现：JSON 模板解析与 `${key}` 占位符替换。

use crate::error::{GarrisonError, GarrisonResult};
use crate::json::GarrisonJsonTemplate;
use std::collections::HashMap;

impl GarrisonJsonTemplate {
    /// 解析含 `${key}` 占位符的 JSON 字符串为模板；解析失败返回 `Internal` 错误（消息含 json-template-parse）。
    pub fn new(template: &str) -> GarrisonResult<Self> {
        let value: serde_json::Value = serde_json::from_str(template)
            .map_err(|e| GarrisonError::Internal(format!("json-template-parse::{}", e)))?;
        Ok(Self { value })
    }

    /// 递归替换 `${key}` 占位符并序列化为 JSON 字符串；未提供的 `${key}` 保留原样。
    ///
    /// 单遍扫描：占位符仅从模板原文识别并替换一次，替换值中的 `${key}` 不二次替换；输出与 `params` 顺序无关、确定。
    pub fn render(&self, params: &HashMap<String, String>) -> GarrisonResult<String> {
        let rendered = render_value(&self.value, params);
        serde_json::to_string(&rendered)
            .map_err(|e| GarrisonError::Internal(format!("json-serialize::{}", e)))
    }

    /// 获取内部 `Value` 的引用（便于直接访问）。
    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }
}

/// 递归替换 `Value` 中的 `${key}` 占位符（借用输入返回新树，无占位符的字符串节点直接克隆）。
fn render_value(value: &serde_json::Value, params: &HashMap<String, String>) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            if s.contains("${") {
                serde_json::Value::String(substitute(s, params))
            } else {
                value.clone()
            }
        },
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), render_value(v, params));
            }
            serde_json::Value::Object(out)
        },
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(|v| render_value(v, params)).collect())
        },
        _ => value.clone(),
    }
}

/// 单遍扫描 O(n) 替换 `s` 中的 `${key}`（哈希查表）：仅识别模板原文占位符，替换值不再扫描；未提供或无闭合 `}` 的占位符原样保留。
fn substitute(s: &str, params: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) => {
                let key = &after[..end];
                match params.get(key) {
                    Some(val) => out.push_str(val),
                    None => {
                        out.push_str("${");
                        out.push_str(key);
                        out.push('}');
                    },
                }
                rest = &after[end + 1..];
            },
            None => {
                out.push_str("${");
                rest = after;
            },
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 替换值中包含其他占位符时不得二次替换。
    #[test]
    fn substitute_does_not_rescan_replacement_values() {
        let mut params = HashMap::new();
        params.insert("a".to_string(), "${b}".to_string());
        params.insert("b".to_string(), "X".to_string());
        // 单遍扫描：替换值中的 ${b} 必须原样保留，不二次展开
        assert_eq!(substitute("v=${a}", &params), "v=${b}");
    }

    /// 输出与 params 迭代顺序无关（确定性）。
    #[test]
    fn substitute_is_deterministic() {
        let mut params = HashMap::new();
        params.insert("b".to_string(), "X".to_string());
        params.insert("a".to_string(), "${b}".to_string());
        let first = substitute("${a} ${b}", &params);
        let second = substitute("${a} ${b}", &params);
        assert_eq!(first, second);
        assert_eq!(first, "${b} X");
    }

    /// 未提供的占位符与未闭合的 `${` 原样保留。
    #[test]
    fn substitute_keeps_unmatched_and_unclosed() {
        let params: HashMap<String, String> = HashMap::new();
        assert_eq!(substitute("a=${a} b=${b}", &params), "a=${a} b=${b}");
        assert_eq!(substitute("unclosed ${oops", &params), "unclosed ${oops");
    }

    /// 嵌套结构渲染借用语义（功能不变）。
    #[test]
    fn render_nested_structures() {
        let template =
            GarrisonJsonTemplate::new(r#"{"o":{"s":"${x}"},"arr":["${x}",1,null],"n":5}"#).unwrap();
        let mut params = HashMap::new();
        params.insert("x".to_string(), "v".to_string());
        // JSON 键序为实现细节（BTreeMap/IndexMap 不同），断言按 Value 语义比较，不锁键序
        let rendered: serde_json::Value =
            serde_json::from_str(&template.render(&params).unwrap()).unwrap();
        let expected: serde_json::Value =
            serde_json::from_str(r#"{"o":{"s":"v"},"arr":["v",1,null],"n":5}"#).unwrap();
        assert_eq!(rendered, expected);
    }
}
