//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! `GarrisonJsonTemplate` 实现：JSON 模板解析与 `${key}` 占位符替换。

use crate::error::{GarrisonError, GarrisonResult};
use crate::json::GarrisonJsonTemplate;
use std::collections::HashMap;

impl GarrisonJsonTemplate {
    /// 解析 JSON 字符串为模板。
    ///
    /// # 参数
    /// - `template`: JSON 字符串，可包含 `${key}` 占位符。
    ///
    /// # 返回
    /// - `Ok(Self)`: 解析成功，struct 内部持有解析后的 `Value`。
    /// - `Err(GarrisonError::Internal)`: JSON 解析失败，消息含解析错误信息。
    pub fn new(template: &str) -> GarrisonResult<Self> {
        let value: serde_json::Value = serde_json::from_str(template)
            .map_err(|e| GarrisonError::Internal(format!("json-template-parse::{}", e)))?;
        Ok(Self { value })
    }

    /// 递归替换 `${key}` 占位符并序列化为 JSON 字符串。
    ///
    /// # 参数
    /// - `params`: 占位符键值对。未在 `params` 中提供的 `${key}` 保留原样。
    ///
    /// # 替换语义（ocr #6595）
    ///
    /// 单遍扫描：占位符仅从**模板原文**中识别并替换一次，替换值本身即使包含
    /// `${key}` 也不会被二次替换；遍历顺序与 `params` 无关，输出确定。
    ///
    /// # 性能（ocr #5510/6051）
    ///
    /// 渲染借用内部 `Value`（`&self`），按需构建新树：无占位符的字符串节点
    /// 原样克隆，不再整树深拷贝 + 逐节点二次 clone。
    ///
    /// # 返回
    /// - `Ok(String)`: 渲染后的 JSON 字符串（可被 `serde_json::from_str` 再次解析）。
    /// - `Err(GarrisonError::Internal)`: 序列化失败。
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

/// 递归替换 `Value` 中的 `${key}` 占位符（借用输入，返回新树）。
///
/// - `String` 类型: 执行占位符替换（含占位符时才分配新 String）
/// - `Object` 类型: 递归处理每个值
/// - `Array` 类型: 递归处理每个元素
/// - 其他类型: 克隆原样返回
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

/// 单遍扫描替换 `s` 中的 `${key}` 占位符。
///
/// - 仅识别模板原文中的占位符，替换值不会被再次扫描（杜绝二次替换，ocr #6595）；
/// - 单次遍历 O(n)（哈希查表，与参数数量 k 无关，ocr #5510）；
/// - 未在 `params` 中的 `${key}` 原样保留；无闭合 `}` 的 `${` 同样原样保留。
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
                        // 占位符未提供：原样保留
                        out.push_str("${");
                        out.push_str(key);
                        out.push('}');
                    },
                }
                rest = &after[end + 1..];
            },
            None => {
                // 无闭合 '}'：原样保留并继续扫描剩余部分
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

    /// 替换值中包含其他占位符时不得二次替换（ocr #6595）。
    #[test]
    fn substitute_does_not_rescan_replacement_values() {
        let mut params = HashMap::new();
        params.insert("a".to_string(), "${b}".to_string());
        params.insert("b".to_string(), "X".to_string());
        // 旧实现按 HashMap 顺序连续 replace 时，${b} 可能被展开为 X（不确定输出）；
        // 单遍扫描后替换值 ${b} 必须原样保留
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
        // JSON 键序为实现细节（serde_json 默认按字母序排序输出），不保证插入序。
        assert_eq!(
            template.render(&params).unwrap(),
            r#"{"arr":["v",1,null],"n":5,"o":{"s":"v"}}"#
        );
    }
}
