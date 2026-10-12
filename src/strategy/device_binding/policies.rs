// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 设备绑定策略共用实现:`check_is_new_device` 工具函数(供 StrictBinding/LooseBinding 复用)与 Disabled 策略。

use crate::error::GarrisonResult;
use async_trait::async_trait;

use super::DeviceBindingPolicy;

/// 检查 `device_id` 是否为 `login_id` 的新设备:任一 token session 的 `device` 匹配即已知,无历史 session 视为新设备。
///
/// 安全语义:空 `device_id` 返回 `Ok(false)`(视为已知设备并 warn),攻击者可省略 device 字段绕过设备绑定与二级认证;
/// 需要 fail-closed 的部署必须在上游拒绝空设备标识(调用方 `stp` 层 helpers 对空 `device_id` 直接跳过整个检查,不会走到本函数)。
pub(super) async fn check_is_new_device(
    session: &crate::session::GarrisonSession,
    login_id: &str,
    device_id: &str,
) -> GarrisonResult<bool> {
    // 空设备标识视为已知设备,跳过绑定检测(绕过向量见上方文档),显式 warn 留痕。
    if device_id.is_empty() {
        tracing::warn!(
            login_id,
            "check_is_new_device: empty device_id treated as known device (device binding check skipped; reject empty device upstream for fail-closed)"
        );
        return Ok(false);
    }

    let tokens = session.get_tokens_by_login_id(login_id);
    if tokens.is_empty() {
        return Ok(true);
    }

    for token in &tokens {
        if let Some(ts) = session.get_token_session(token).await? {
            if ts.device.as_deref() == Some(device_id) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// 完全禁用设备绑定:两个方法均返回 `Ok(false)`,零成本占位策略。
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
