//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 设备绑定策略共用实现:Disabled 策略与新设备检测工具函数。
//!
//! 本文件聚集不适合放在 `strict` / `loose` 子模块的策略实现与共用工具:
//! - `check_is_new_device`:遍历 `login_id` 的历史 `TokenSession` 判断设备是否为新设备
//! - [`Disabled`] —— 完全禁用设备绑定的零成本占位策略
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
/// # 空设备标识（issue #3687/#2164：显式声明 fail 语义）
///
/// 空 `device_id` 返回 `Ok(false)`（视为已知设备,跳过检测）并 `tracing::warn!`。
/// **安全语义**：`Ok(false)` 意味着空设备标识的登录会绕过新设备检测与
/// 二级认证——这是与调用方 `stp` 层 helpers 对齐的既有设计（`check_device_binding`
/// 对空 `device_id` 直接跳过整个检查,不会走到本函数）,但直接调用方必须意识到：
/// 攻击者可省略 device 字段规避设备绑定。需要 fail-closed 的部署应在上游
/// 拒绝空设备标识的登录,而非依赖本函数拦截。
///
/// # 无历史 session
///
/// 无历史 session 时返回 `Ok(true)`（视为新设备）。
pub(super) async fn check_is_new_device(
    session: &crate::session::GarrisonSession,
    login_id: &str,
    device_id: &str,
) -> GarrisonResult<bool> {
    // 空设备标识不视为新设备（避免无设备信息的登录被错误阻断）。
    // 注意：此路径同时跳过设备绑定检测（绕过向量,见上方文档）,显式 warn 留痕。
    if device_id.is_empty() {
        tracing::warn!(
            login_id,
            "check_is_new_device: empty device_id treated as known device (device binding check skipped; reject empty device upstream for fail-closed)"
        );
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
