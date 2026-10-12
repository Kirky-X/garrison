// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 权限校验模块：定义以 login_id 为入参（与 token 风格无关）的权限与角色校验抽象；
//! [`decision`](crate::core::permission::decision) 子模块提供 `Decision` / `DecisionReason` /
//! `AuthRequest` 决策溯源。

pub mod decision;

use async_trait::async_trait;
use std::sync::Arc;
use unicode_normalization::UnicodeNormalization;

use crate::error::{GarrisonError, GarrisonResult};
use crate::stp::GarrisonInterface;

pub use decision::{AuthRequest, Decision, DecisionReason};

/// 权限注册表模块。
#[cfg(feature = "core-advanced")]
pub mod registry;

#[cfg(feature = "core-advanced")]
pub use registry::{PermissionRegistration, PermissionRegistry, PermissionSpec};

/// 请求对象式授权器模块。
#[cfg(feature = "authorize-api")]
pub mod authorize;

#[cfg(feature = "authorize-api")]
pub use authorize::Authorizer;

/// 决策组合器模块（forbid 优先语义）。
#[cfg(feature = "core-advanced")]
pub mod decision_combinator;

#[cfg(feature = "core-advanced")]
pub use decision_combinator::DecisionCombinator;

/// 权限校验 trait：入参 `login_id: &str`（与 token 风格无关），须用 `#[async_trait]` 标注、
/// 绑定 `Send + Sync`；[`authorize`](Self::authorize) 支持决策溯源，`check_permission` /
/// `check_role` 为默认实现（委托 authorize 并返回断言结果）。
#[async_trait]
pub trait PermissionChecker: Send + Sync {
    /// 校验主体是否持有指定权限；权限字符串为空返回 `Err(GarrisonError::InvalidParam)`。
    async fn has_permission(&self, login_id: &str, permission: &str) -> GarrisonResult<bool>;

    /// 校验主体是否持有指定角色。
    async fn has_role(&self, login_id: &str, role: &str) -> GarrisonResult<bool>;

    /// 校验主体在指定租户下是否持有指定权限（租户感知数据源）；默认实现忽略 `tenant_id` 委托
    /// [`has_permission`](Self::has_permission)（数据源未按租户隔离则无需覆写）。
    ///
    /// [`authorize`](Self::authorize) 默认实现消费 `AuthRequest.tenant_id`：非 0 时改走本方法
    /// （0 = 单租户/未隔离，语义等同 `has_permission`）。`PermissionCheckerDefault` 覆写为委托
    /// `GarrisonInterface::get_permission_list_in_tenant`：覆写了该回调的业务方获得真实租户作用域判定。
    async fn has_permission_in_tenant(
        &self,
        _tenant_id: i64,
        login_id: &str,
        permission: &str,
    ) -> GarrisonResult<bool> {
        self.has_permission(login_id, permission).await
    }

    /// 鉴权决策：默认实现调 [`has_permission`](Self::has_permission) 并构造 [`Decision`]
    /// （持有 → ExplicitAllow，未持有 → NoMatchingPermission），`request.tenant_id` 非 0 时改走
    /// [`has_permission_in_tenant`](Self::has_permission_in_tenant)。覆写者应自行消费 `tenant_id`
    /// 或在文档声明租户语义边界。
    ///
    /// `decision-trace` feature 启用时自动生成 UUID v7（时间有序）作 `trace_id`，否则为 `None`
    /// （性能优先）；实现者可覆盖以填充 `checked_permissions` / `matched_roles`。校验过程出错
    /// 返回 `Err(GarrisonError)`，"未持有权限"不是错误（返回 `Ok(Decision { allowed: false, .. })`）。
    async fn authorize(&self, request: &AuthRequest) -> GarrisonResult<Decision> {
        // decision-trace 启用时生成 UUID v7 trace_id（时间有序，便于跨服务追踪）。
        #[cfg(feature = "core-advanced")]
        let trace_id = Some(uuid::Uuid::now_v7().to_string());
        #[cfg(not(feature = "core-advanced"))]
        let trace_id: Option<String> = None;

        // tenant_id 非 0 走租户感知路径（默认委托 has_permission；0 = 单租户/未隔离）。
        let allowed = if request.tenant_id != 0 {
            self.has_permission_in_tenant(request.tenant_id, &request.login_id, &request.action)
                .await?
        } else {
            self.has_permission(&request.login_id, &request.action)
                .await?
        };
        let decision = if allowed {
            Decision {
                allowed: true,
                reason: DecisionReason::ExplicitAllow,
                errors: Vec::new(),
                checked_permissions: Vec::new(),
                matched_roles: Vec::new(),
                trace_id,
            }
        } else {
            Decision {
                allowed: false,
                reason: DecisionReason::NoMatchingPermission,
                errors: Vec::new(),
                checked_permissions: Vec::new(),
                matched_roles: Vec::new(),
                trace_id,
            }
        };
        Ok(decision)
    }

    /// 断言权限：被拒绝时返回 `Err(GarrisonError::NotPermission)`（默认实现委托
    /// [`authorize`](Self::authorize)）。
    async fn check_permission(&self, login_id: &str, permission: &str) -> GarrisonResult<()> {
        let request = AuthRequest::new(login_id, permission);
        let decision = self.authorize(&request).await?;
        if decision.allowed {
            Ok(())
        } else {
            Err(GarrisonError::NotPermission(format!(
                "core-account-no-permission::{}::{}",
                login_id, permission
            )))
        }
    }

    /// 断言角色：被拒绝时返回 `Err(GarrisonError::NotRole)`。
    async fn check_role(&self, login_id: &str, role: &str) -> GarrisonResult<()> {
        if self.has_role(login_id, role).await? {
            Ok(())
        } else {
            Err(GarrisonError::NotRole(format!(
                "core-account-no-role::{}::{}",
                login_id, role
            )))
        }
    }

    /// 批量校验权限：任一满足即返回 true（内部调 `has_permission`，错误按 fail-closed 视为不满足）。
    ///
    /// 返回 `bool` 而非 `Result` 是公开 API 契约（变更会破坏实现方/调用方），底层错误无法经返回值
    /// 表达：故障降级为「不满足」是 fail-closed 的可用性代价——攻击者诱发临时 DAO 故障即可拒绝合法
    /// 用户的授权判定；默认实现（`PermissionCheckerDefault`）在错误路径逐条 `tracing::warn!`
    /// （含 login_id / permission / 错误详情）可对接告警。需区分「无权限」与「故障」时用
    /// [`authorize()`](Self::authorize)（返回 `GarrisonResult<Decision>`，错误显性化，不降级）。
    async fn has_any_permission(&self, login_id: &str, perms: &[&str]) -> bool;

    /// 批量校验权限：全部满足才返回 true；错误处理语义同
    /// [`has_any_permission`](Self::has_any_permission)——fail-closed 降级 + warn，需错误通道时用
    /// [`authorize()`](Self::authorize)。
    async fn has_all_permissions(&self, login_id: &str, perms: &[&str]) -> bool;
}

/// `PermissionChecker` 的默认实现，委托 `GarrisonInterface` 获取权限/角色数据后做字符串匹配
///（纯数据查询，返回 bool/Err 无副作用；校验编排、抛异常与事件广播归 `GarrisonPermissionStrategy`）。
pub struct PermissionCheckerDefault {
    /// 业务接口（提供 get_permission_list / get_role_list）。
    interface: Arc<dyn GarrisonInterface>,
}

/// `PermissionCheckerDefault` 实现块（mod.rs 接口隔离约定：仅保留接口定义）。
pub mod default;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
