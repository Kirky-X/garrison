//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 设备绑定策略共用实现:Disabled 策略与新设备检测工具函数。
//!
//! 本文件聚集不适合放在 `strict` / `loose` 子模块的策略实现与共用工具:
//! - `check_is_new_device`:遍历 `login_id` 的历史 `TokenSession` 判断设备是否为新设备
//! - [`Disabled`]:完全禁用设备绑定的零成本占位策略（T012）
//!
//! `check_is_new_device` 由 `StrictBinding` 与
//! `LooseBinding` 复用,通过 `super::policies::check_is_new_device` 路径直接访问。

use crate::error::GarrisonResult;
use async_trait::async_trait;

use super::DeviceBindingPolicy;

/// 检查指定 `device_id` 是否为 `login_id` 的新设备。
///
/// 通过遍历 `login_id` 的所有 token session,检查是否有 session 的 `device` 字段
/// 匹配 `device_id`。任一 session 匹配则视为已知设备,全部不匹配则视为新设备。
///
/// # 空设备标识
///
/// 空 `device_id` 返回 `Ok(false)`（无设备标识不视为新设备）,
/// 避免无设备信息的登录被错误阻断。
///
/// # 无历史 session
///
/// 无历史 session 时返回 `Ok(true)`（视为新设备）。
pub(super) async fn check_is_new_device(
    session: &crate::session::GarrisonSession,
    login_id: &str,
    device_id: &str,
) -> GarrisonResult<bool> {
    // 空设备标识不视为新设备（避免无设备信息的登录被错误阻断）
    if device_id.is_empty() {
        return Ok(false);
    }

    let tokens = session.get_tokens_by_login_id(login_id);
    // 无历史 session 视为新设备
    if tokens.is_empty() {
        return Ok(true);
    }

    // 遍历所有 TokenSession,任一 device 匹配则视为已知设备
    for token in &tokens {
        if let Some(ts) = session.get_token_session(token).await? {
            if ts.device.as_deref() == Some(device_id) {
                return Ok(false);
            }
        }
    }
    // 所有 session 的 device 都不匹配 → 新设备
    Ok(true)
}

/// 禁用设备绑定策略:完全关闭新设备检测与二级认证。
///
/// `is_new_device` 与 `require_secondary_auth` 均返回 `Ok(false)`,
/// 适用于不启用设备绑定检查的部署。无需持有任何引用,可作为零成本占位策略。
#[derive(Debug, Default)]
pub struct Disabled;

#[async_trait]
impl DeviceBindingPolicy for Disabled {
    async fn is_new_device(&self, _login_id: &str, _device_id: &str) -> GarrisonResult<bool> {
        Ok(false)
    }

    async fn require_secondary_auth(
        &self,
        _login_id: &str,
        _device_id: &str,
    ) -> GarrisonResult<bool> {
        Ok(false)
    }
}
