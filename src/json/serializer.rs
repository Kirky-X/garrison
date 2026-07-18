//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `BulwarkSerializerDefault` 实现：委托 `serde_json` 的默认序列化/反序列化。

use crate::error::{BulwarkError, BulwarkResult};
use crate::json::{BulwarkSerializer, BulwarkSerializerDefault};

impl BulwarkSerializer for BulwarkSerializerDefault {
    fn serialize<T: serde::Serialize>(&self, value: &T) -> BulwarkResult<String> {
        serde_json::to_string(value)
            .map_err(|e| BulwarkError::Internal(format!("json-serialize::{}", e)))
    }

    fn deserialize<T: serde::de::DeserializeOwned>(&self, json: &str) -> BulwarkResult<T> {
        serde_json::from_str(json)
            .map_err(|e| BulwarkError::Internal(format!("json-deserialize::{}", e)))
    }
}
