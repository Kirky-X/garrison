// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! API Key 协议模块（对应 API 接口鉴权能力）：生成/校验/吊销/轮换，适用于服务间
//! 调用与开放 API。仅在启用 `protocol-apikey` 特性时编译。
//!
//! ## Key 命名空间
//!
//! `garrison:apikey:<namespace>:<key_id>`，支持多租户/多场景隔离。
//!
//! ## 凭证格式与哈希存储（CWE-916）
//!
//! `key_id.key_secret` 双段格式（各 32 hex，`.` 分隔）：`key_id` 为公开标识（可入
//! 审计日志），`key_secret` 永不落库——仅存 `sha256(key_secret)` 到
//! `ApiKeyInfo::secret_hash`，校验用常量时间比较（`subtle::ConstantTimeEq`），
//! 数据库/KV 泄露也无法还原 secret。
//!
//! `verify` 只接受双段格式（fail-closed：不含 `.` 的输入无法定位存储记录，直接
//! 返回 `InvalidToken`，杜绝任何"按存在性校验"的路径（CWE-916 强化）)。

use crate::dao::GarrisonDao;
// listener_manager 注入（feature-gated）
#[cfg(feature = "listener")]
use crate::listener::GarrisonListenerManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod handler;

/// API Key 元数据（`namespace`/`key_id`/`secret_hash`/`created_at` 反序列化必需，
/// 缺失即失败）。
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
    /// 命名空间（默认 `"default"`，与存储路径 `garrison:apikey:<namespace>:<key_id>`
    /// 中的 namespace 严格一致）。
    pub namespace: String,
    /// 公开 key 标识（32 hex；存储 key 后缀，可安全记录到日志用于审计）。
    pub key_id: String,
    /// `sha256(key_secret)` 的 hex 编码（64 字符）。
    ///
    /// **不存储明文 secret**（CWE-916）；校验时用常量时间比较。
    pub secret_hash: String,
    /// 归属主体标识（IDOR 防护，生成时默认等于 `login_id`）。
    ///
    /// **注意**：`verify` / `verify_with_namespace` **不校验**该字段与请求主体的
    /// 关系（框架不持有主体上下文）。归属（IDOR）校验属应用层契约：调用方取得
    /// 返回的 `ApiKeyInfo` 后应自行比较 `info.owner_id` 与请求主体再做授权决策。
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
    /// 创建时间戳（秒）：`max_age_secs` 生命周期策略依据（`created_at + max_age_secs
    /// < now` 时拒绝）。
    pub created_at: i64,
}

/// API Key 作用域枚举（类型安全的常见作用域）：规范字符串供
/// [`ApiKeyHandler::with_allowed_scopes`] 允许列表使用；存储层以 `Vec<String>` 保存。
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

/// API Key 处理器：持有 `Arc<dyn GarrisonDao>` 用于 API Key 存储。
pub struct ApiKeyHandler {
    /// DAO 抽象层，用于 API Key 存储。
    dao: Arc<dyn GarrisonDao>,
    /// 可选监听器管理器，注入后 rotate 广播 TokenRotate 事件
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<GarrisonListenerManager>>,
    /// 作用域允许列表（opt-in）：`None` 不校验（允许任意 scope）；`Some(list)` 时
    /// `generate` 拒绝列表外 scope（`InvalidParam`）。
    pub(crate) allowed_scopes: Option<Vec<String>>,
    /// `verify` 成功后节流更新 `last_used_at`（opt-in，默认 `false` 保持 verify
    /// 只读语义）。
    pub(crate) track_last_used: bool,
    /// API Key 最大生命周期（秒）：`None` 不检查（仅依赖 `expire_at`）；
    /// `Some(secs)` 时 verify 检查 `created_at + secs >= now`，超期拒绝。
    pub(crate) max_age_secs: Option<i64>,
    /// 允许无命名空间的 `verify()` 全局校验（默认 `false`，fail-closed）。
    ///
    /// `verify()` 经反向索引可校验**任意** namespace 的 key，与租户隔离语义冲突；
    /// 默认禁用，无 namespace 校验必须走 `verify_with_namespace`。确有全局校验需求
    /// 的部署可经 `with_allow_global_verify(true)` 显式放开（开启时输出 warn）。
    pub(crate) allow_global_verify: bool,
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
