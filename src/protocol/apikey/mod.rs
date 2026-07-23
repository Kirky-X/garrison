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
//! v0.4.2 起，所有 API Key 存储格式由 `garrison:apikey:<key>` 升级为
//! `garrison:apikey:<namespace>:<key>`，支持多租户/多场景隔离。
//!
//! ## 凭证格式与哈希存储（CWE-916 修复）
//!
//! v0.7.x 起，API Key 采用 `key_id.key_secret` 双段格式（各 32 hex，`.` 分隔）：
//! - `key_id`：公开标识，作为存储 key 后缀（`garrison:apikey:<ns>:<key_id>`），可安全记录到日志用于审计。
//! - `key_secret`：机密部分，**永不落库**；仅存储 `sha256(key_secret)` 到 `ApiKeyInfo::secret_hash`，
//!   校验时用常量时间比较（`subtle::ConstantTimeEq`）。数据库/KV 泄露也无法还原 secret。
//!
//! `verify` 拒绝旧格式（v0.4.1 无 namespace 单 token、v0.4.2 带 namespace 单 token）：
//! 旧 key 的 `ApiKeyInfo::secret_hash` 为空，被 `decode_and_check` fail-closed 拒绝
//! （返回 `apikey-legacy-secret-required`），强制迁移到 v0.7.x 双段格式（W8，CWE-916 强化）。

use crate::dao::GarrisonDao;
// listener_manager 注入（feature-gated）
#[cfg(feature = "listener")]
use crate::listener::GarrisonListenerManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod handler;

/// API Key 元数据。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
    /// - 与 key 存储路径 `garrison:apikey:<namespace>:<key_id>` 中的 namespace 严格一致
    #[serde(default = "handler::default_namespace")]
    pub namespace: String,
    /// 公开 key 标识（32 hex）。
    ///
    /// 作为存储 key 后缀，可安全记录到日志用于审计。
    /// 旧 JSON（无此字段）反序列化为空串，仅作为 legacy key 查找路径的标识，
    /// 最终仍被 `decode_and_check` fail-closed 拒绝（见 W8）。
    #[serde(default)]
    pub key_id: String,
    /// `sha256(key_secret)` 的 hex 编码（64 字符）。
    ///
    /// **不存储明文 secret**（CWE-916 修复）。校验时用常量时间比较。
    /// 旧 JSON（无此字段）反序列化为空串，此时 fail-closed 拒绝（返回
    /// `apikey-legacy-secret-required`），不做 secret 比较也不按存在性放行。
    #[serde(default)]
    pub secret_hash: String,
    /// 归属主体标识（IDOR 防护，#3）。
    ///
    /// 生成时默认等于 `login_id`。用于标识 key 的拥有者，供审计与归属校验。
    #[serde(default)]
    pub owner_id: Option<String>,
    /// 最后使用时间戳（秒）。
    ///
    /// 仅在 handler 启用 `with_last_used_tracking(true)` 时，`verify` 成功后节流更新。
    #[serde(default)]
    pub last_used_at: Option<i64>,
    /// 每 key 速率上限（请求/窗口），`None` 表示不限制。
    ///
    /// 由 `limiteron` quota 在请求路径按 `key_id` 实施。
    #[serde(default)]
    pub rate_limit: Option<u32>,
}

/// API Key 作用域枚举（类型安全的常见作用域）。
///
/// 提供规范的作用域字符串，供构建 [`ApiKeyHandler::with_allowed_scopes`] 的允许列表使用。
/// 存储层仍以 `Vec<String>` 形态保存（向后兼容），本枚举仅用于减少手写字符串的拼写错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyScope {
    /// 只读。
    Read,
    /// 读写。
    Write,
    /// 管理员。
    Admin,
}

impl ApiKeyScope {
    /// 返回作用域的规范字符串表示。
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiKeyScope::Read => "read",
            ApiKeyScope::Write => "write",
            ApiKeyScope::Admin => "admin",
        }
    }
}

impl std::fmt::Display for ApiKeyScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// API Key 处理器。
///
/// 持有 `Arc<dyn GarrisonDao>` 用于 API Key 存储。
/// 实现 `Send + Sync`，可在多线程环境共享。
pub struct ApiKeyHandler {
    /// DAO 抽象层，用于 API Key 存储。
    dao: Arc<dyn GarrisonDao>,
    /// 可选监听器管理器，注入后 rotate 广播 TokenRotate 事件
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<GarrisonListenerManager>>,
    /// 作用域允许列表（opt-in，#6）。
    ///
    /// - `None`（默认）：不校验 scopes，保持向后兼容。
    /// - `Some(list)`：`generate` 时拒绝不在列表中的 scope（返回 `InvalidParam`）。
    pub(crate) allowed_scopes: Option<Vec<String>>,
    /// 是否在 `verify` 成功后节流更新 `last_used_at`（opt-in，#7-b）。
    ///
    /// 默认 `false`：`verify` 保持只读语义（无副作用写入），与历史行为一致。
    pub(crate) track_last_used: bool,
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
