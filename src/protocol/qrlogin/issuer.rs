// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 扫码登录会话签发端口（DIP）。
//!
//! 协议层只依赖本 trait：`resolve_app_login_id` 从 App 会话 token 解析确认者，
//! `issue_session` 为确认者签发新会话。协议层不依赖 stp/server——server 层提供
//! 基于 `GarrisonManager` 的默认实现（内部构造 `LoginParams`，device 固定
//! "qrlogin"），测试提供 mock。

use crate::error::GarrisonResult;
use async_trait::async_trait;

/// 扫码登录会话签发端口。
#[async_trait]
pub trait QrLoginSessionIssuer: Send + Sync {
    /// 从 App 端会话 token 解析确认者 login_id。
    ///
    /// token 无效/过期/未登录时返回 `Err`（HTTP 层映射为 401）。
    async fn resolve_app_login_id(&self, app_token: &str) -> GarrisonResult<String>;

    /// 为确认者签发新会话 token。
    ///
    /// 实现方须走与密码登录完全相同的签发路径（`SessionLogic::login`），使扫码
    /// 登录会话继承全部下游能力（权限/踢下线/续期/hijack 检测/审计）。
    async fn issue_session(&self, login_id: &str) -> GarrisonResult<String>;
}
