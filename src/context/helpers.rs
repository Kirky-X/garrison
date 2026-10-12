// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Context 模块辅助函数。
//!
//! `effective_is_read_header` / `effective_is_read_cookie` 目前未接入任何适配器的 token 提取路径
//! （`token_extract` 直接读 `config.is_read_header` / `is_read_cookie`），仅作前后端分离语义的
//! 参考实现保留并导出：`frontend_separation=true` 只在响应写入侧生效，适配器若后续接入应改用这两个函数。

/// 前后端分离模式下有效的 Header 读取开关：`frontend_separation=true` 时强制返回 `true`，忽略 `is_read_header`。
pub fn effective_is_read_header(config: &crate::config::GarrisonConfig) -> bool {
    config.is_read_header || config.frontend_separation
}

/// 前后端分离模式下有效的 Cookie 读取开关：`frontend_separation=true` 时强制返回 `false`，忽略 `is_read_cookie`。
pub fn effective_is_read_cookie(config: &crate::config::GarrisonConfig) -> bool {
    config.is_read_cookie && !config.frontend_separation
}

/// 无配置版 `set_cookie` 共享的默认配置（进程级 `OnceLock` 缓存）；
/// `GarrisonConfig::default_config()` 全字段确定可安全共享，缓存避免兜底路径每次重建配置的堆分配与 watch channel 创建。
pub(crate) fn shared_default_config() -> &'static crate::config::GarrisonConfig {
    use std::sync::OnceLock;
    static SHARED_DEFAULT_CONFIG: OnceLock<crate::config::GarrisonConfig> = OnceLock::new();
    SHARED_DEFAULT_CONFIG.get_or_init(crate::config::GarrisonConfig::default_config)
}
