//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `RedisDeploymentMode` 与 `RedisConfig` 的 trait 实现分离文件。
//!
//! 遵循规则 25（mod/crate 接口隔离）：mod.rs 只保留 trait 定义、struct/enum
//! 定义、pub use re-export、mod 声明；impl 块迁移至本文件。

use crate::dao::{RedisConfig, RedisDeploymentMode};

/// Default 实现，返回 Single 模式（`redis://127.6379`）。
///
/// 供 `RedisConfig` 的 `#[serde(default)]` 在反序列化时填充缺失的 `mode` 字段。
impl Default for RedisDeploymentMode {
    fn default() -> Self {
        RedisDeploymentMode::Single {
            url: "redis://127.0.0.1:6379".to_string(),
        }
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            mode: RedisDeploymentMode::Single {
                url: "redis://127.0.0.1:6379".to_string(),
            },
            password: None,
            db: 0,
            connection_timeout_secs: 5,
            pool_size: 10,
        }
    }
}

/// Display 实现，输出人类可读的部署模式描述。
impl std::fmt::Display for RedisDeploymentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedisDeploymentMode::Single { url } => write!(f, "single({})", url),
            RedisDeploymentMode::Sentinel { master_name, urls } => {
                write!(
                    f,
                    "sentinel(master={}, {} sentinels)",
                    master_name,
                    urls.len()
                )
            },
            RedisDeploymentMode::Cluster { urls } => {
                write!(f, "cluster({} nodes)", urls.len())
            },
            RedisDeploymentMode::MasterSlave {
                master_url,
                slave_urls,
            } => {
                write!(
                    f,
                    "master-slave(master={}, {} slaves)",
                    master_url,
                    slave_urls.len()
                )
            },
        }
    }
}
