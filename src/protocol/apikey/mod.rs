//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API Key 协议模块，提供 API Key 生成/校验/吊销/轮换。
//!
//! 对应 API 接口鉴权能力，
//! 适用于服务间调用与开放 API 场景。
//!
//! 仅在启用 `protocol-apikey` 特性时编译。
//!
//! ## Key 命名空间
//!
//! v0.4.2 起，所有 API Key 存储格式由 `bulwark:apikey:<key>` 升级为
//! `bulwark:apikey:<namespace>:<key>`，支持多租户/多场景隔离。
//! `verify` 兼容旧格式（无 namespace）以保护历史 key 不失效。

use crate::dao::BulwarkDao;
// listener_manager 注入（feature-gated）
#[cfg(feature = "listener")]
use crate::listener::BulwarkListenerManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod handler;

/// API Key 元数据。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKeyInfo {
    /// 登录主体标识。
    pub login_id: String,
    /// 作用域列表。
    pub scopes: Vec<String>,
    /// 过期时间戳（秒）。
    pub expire_at: i64,
    /// 是否已吊销。
    pub revoked: bool,
    /// 命名空间。
    ///
    /// - 新生成 key 必带 namespace（默认 `"default"`）
    /// - 旧 JSON 数据（无 `namespace` 字段）反序列化时通过 `#[serde(default)]` 填充为 `"default"`
    /// - 与 key 存储路径 `bulwark:apikey:<namespace>:<key>` 中的 namespace 严格一致
    #[serde(default = "handler::default_namespace")]
    pub namespace: String,
}

/// API Key 处理器。
///
/// 持有 `Arc<dyn BulwarkDao>` 用于 API Key 存储。
/// 实现 `Send + Sync`，可在多线程环境共享。
pub struct ApiKeyHandler {
    /// DAO 抽象层，用于 API Key 存储。
    dao: Arc<dyn BulwarkDao>,
    /// 可选监听器管理器，注入后 rotate 广播 TokenRotate 事件
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<BulwarkListenerManager>>,
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
