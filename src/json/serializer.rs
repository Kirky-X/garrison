//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `GarrisonSerializerDefault` 实现：委托 `serde_json` 的默认序列化/反序列化。

use crate::error::{GarrisonError, GarrisonResult};
use crate::json::{GarrisonSerializer, GarrisonSerializerDefault};

impl GarrisonSerializer for GarrisonSerializerDefault {
    fn serialize<T: serde::Serialize>(&self, value: &T) -> GarrisonResult<String> {
        serde_json::to_string(value)
            .map_err(|e| GarrisonError::Internal(format!("json-serialize::{}", e)))
    }

    fn deserialize<T: serde::de::DeserializeOwned>(&self, json: &str) -> GarrisonResult<T> {
        serde_json::from_str(json)
            .map_err(|e| GarrisonError::Internal(format!("json-deserialize::{}", e)))
    }
}
