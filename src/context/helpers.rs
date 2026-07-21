//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Context 模块辅助函数（从 mod.rs 迁移，Rule 25 合规）。

/// 前后端分离模式下有效的 Header 读取开关。
///
/// `frontend_separation=true` 时强制返回 `true`（必须从 Authorization Header 读取 Token），
/// 忽略 `is_read_header` 配置。用于 Web 框架适配器的 token 提取逻辑。
pub fn effective_is_read_header(config: &crate::config::GarrisonConfig) -> bool {
    config.is_read_header || config.frontend_separation
}

/// 前后端分离模式下有效的 Cookie 读取开关。
///
/// `frontend_separation=true` 时强制返回 `false`（不读 Cookie），
/// 忽略 `is_read_cookie` 配置。用于 Web 框架适配器的 token 提取逻辑。
pub fn effective_is_read_cookie(config: &crate::config::GarrisonConfig) -> bool {
    config.is_read_cookie && !config.frontend_separation
}
