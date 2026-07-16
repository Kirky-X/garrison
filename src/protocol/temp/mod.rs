//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 临时凭证协议模块，提供短时有效、一次性使用的临时访问凭证。
//!
//! 对应 临时 Token 机制，
//! 适用于邀请码、密码重置链接、邮箱验证码等场景。
//!
//! 仅在启用 `protocol-temp` 特性时编译。
//!
//! ## Key 命名空间
//!
//! 所有临时凭据存储在 `bulwark:temp:<prefix>:<random>` 命名空间下，
//! 与 session/sign/sso/apikey 模块隔离。`prefix` 用于区分业务场景
//! （如 `invite`、`reset`、`verify`），不允许包含 `:` 以避免解析歧义。

use crate::dao::BulwarkDao;
// listener_manager 注入（feature-gated）
#[cfg(feature = "listener")]
use crate::listener::BulwarkListenerManager;
use std::sync::Arc;

pub mod handler;

/// 临时凭证处理器。
///
/// 持有 `Arc<dyn BulwarkDao>` 用于临时凭据存储。
/// 实现 `Send + Sync`，可在多线程环境共享。
pub struct TempCredentialHandler {
    /// DAO 抽象层，用于临时凭据存储。
    dao: Arc<dyn BulwarkDao>,
    /// 可选监听器管理器，注入后 consume 广播 TempCredentialConsumed 事件
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<BulwarkListenerManager>>,
}

#[cfg(test)]
mod tests;
