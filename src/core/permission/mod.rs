// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 权限校验模块，定义以 login_id 为入参的权限与角色校验抽象。
//!
//! 权限认证核心逻辑，对应 `StpLogic.checkPermission / checkRole` 方法。
//!
//! 0.2.0 将 API 改为 login_id-as-input，与 token 格式无关，便于在任意 token 风格下复用。
//!
//! [`decision`](crate::core::permission::decision) 子模块：`Decision` / `DecisionReason` / `AuthRequest`，
//! 支持决策溯源。

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

/// 权限校验 trait，定义以 login_id 为入参的权限与角色校验抽象。
///
/// 所有方法 MUST 使用 `async_trait` 标注，trait 绑定 `Send + Sync`。
/// 入参为 `login_id: &str` 而非 token，使权限校验可在任意 token 风格下复用。
///
/// [`authorize`](Self::authorize) 方法支持决策溯源。
/// `check_permission` / `check_role` 改为默认实现，委托 `authorize` 并返回断言结果。
#[async_trait]
pub trait PermissionChecker: Send + Sync {
    /// 校验主体是否持有指定权限。
    ///
    /// # 返回
    /// - `Ok(true)`: 持有权限。
    /// - `Ok(false)`: 未持有权限。
    /// - `Err(GarrisonError::InvalidParam)`: 权限字符串为空。
    async fn has_permission(&self, login_id: &str, permission: &str) -> GarrisonResult<bool>;

    /// 校验主体是否持有指定角色。
    async fn has_role(&self, login_id: &str, role: &str) -> GarrisonResult<bool>;

    /// 校验主体在指定租户下是否持有指定权限（租户感知数据源）。
    ///
    /// # 默认实现
    ///
    /// 默认实现委托 [`has_permission`](Self::has_permission)（忽略 `tenant_id`），
    /// 数据源未按租户隔离的实现者无需覆写、行为不变。
    ///
    /// # 生产接线（渗透-RBAC-租户维度-1 修复）
    ///
    /// [`authorize`](Self::authorize) 默认实现消费 `AuthRequest.tenant_id`：
    /// `tenant_id != 0` 时改走本方法。`PermissionCheckerDefault` 覆写为委托
    /// `GarrisonInterface::get_permission_list_in_tenant`——覆写了该回调的
    /// 业务方获得真实租户作用域判定；未覆写时行为与全局判定一致。
    ///
    /// # 参数
    /// - `tenant_id`: 租户 ID（0 表示单租户/未隔离，此时语义等同 `has_permission`）。
    /// - `login_id`: 登录主体标识（租户内标识）。
    /// - `permission`: 权限标识字符串。
    async fn has_permission_in_tenant(
        &self,
        _tenant_id: i64,
        login_id: &str,
        permission: &str,
    ) -> GarrisonResult<bool> {
        self.has_permission(login_id, permission).await
    }

    /// 鉴权决策：基于 [`AuthRequest`] 返回完整 [`Decision`]。
    ///
    /// 默认实现调用 [`has_permission`](Self::has_permission) 并构造 [`Decision`]：
    /// - 持有权限 → `Decision { allowed: true, reason: ExplicitAllow, .. }`
    /// - 未持有权限 → `Decision { allowed: false, reason: NoMatchingPermission, .. }`
    ///
    /// # 租户维度（渗透-RBAC-租户维度-1 修复）
    ///
    /// 默认实现消费 `request.tenant_id`：非 0 时改调
    /// [`has_permission_in_tenant`](Self::has_permission_in_tenant)
    /// （默认委托 `has_permission`，行为不变；`PermissionCheckerDefault` 覆写为
    /// 租户感知数据源）。`tenant_id == 0`（单租户/未隔离）时行为与旧版完全一致。
    /// 实现者若覆写 `authorize`，应自行消费 `tenant_id` 或在文档声明租户语义边界。
    ///
    /// `decision-trace` feature 启用时，默认实现自动生成 UUID v7（时间有序）作为
    /// `trace_id`；不启用时 `trace_id` 为 `None`（性能优先）。
    /// 实现者可覆盖此方法填充 `checked_permissions` / `matched_roles` 字段。
    ///
    /// # 错误
    ///
    /// 校验过程本身出错（如 DAO 故障、参数无效）返回 `Err(GarrisonError)`；
    /// "未持有权限"不是错误，返回 `Ok(Decision { allowed: false, .. })`。
    async fn authorize(&self, request: &AuthRequest) -> GarrisonResult<Decision> {
        // decision-trace feature 启用时自动生成 UUID v7 作为 trace_id
        // （时间有序，便于跨服务追踪与日志关联）；不启用时为 None，避免性能开销。
        #[cfg(feature = "core-advanced")]
        let trace_id = Some(uuid::Uuid::now_v7().to_string());
        #[cfg(not(feature = "core-advanced"))]
        let trace_id: Option<String> = None;

        // 消费 request.tenant_id：非 0 时走租户感知路径（默认委托 has_permission，
        // 无租户维度数据源时行为不变；0 = 单租户/未隔离，与旧版完全一致）。
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

    /// 断言权限：被拒绝时返回 `Err(GarrisonError::NotPermission)`。
    ///
    /// 默认实现委托 [`authorize`](Self::authorize)。
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

    /// 批量校验权限：任一满足即返回 true。
    ///
    /// 内部调用 `has_permission`，遇到错误时该权限按 fail-closed 视为不满足。
    ///
    /// # 错误处理说明
    ///
    /// 返回类型为 `bool` 而非 `GarrisonResult<bool>`（trait 公开 API，变更会破坏
    /// 所有实现方与调用方），底层 `has_permission` 的错误（如 DAO 不可达、超时）
    /// 无法通过返回值表达。语义与可观测性契约：
    ///
    /// - **fail-closed 的可用性代价（安全敏感）**：底层存储故障会被降级为
    /// 「不满足」——攻击者若能诱发临时 DAO 故障，可借此拒绝合法用户的授权判定。
    /// - **故障不再静默**：默认实现（`PermissionCheckerDefault`）在错误路径逐条
    /// 输出 `tracing::warn!`（含 login_id / permission / 错误详情），可对接告警。
    /// - **需要区分「无权限」与「故障」时**：请使用 [`authorize()`](Self::authorize)
    /// （返回 `GarrisonResult<Decision>`，错误显性化，不降级）。
    async fn has_any_permission(&self, login_id: &str, perms: &[&str]) -> bool;

    /// 批量校验权限：全部满足才返回 true。
    ///
    /// 内部调用 `has_permission`，遇到错误时该权限按 fail-closed 视为不满足。
    ///
    /// # 错误处理说明
    ///
    /// 同 [`has_any_permission`](Self::has_any_permission)：返回 `bool`，底层错误
    /// fail-closed 降级并输出 `warn` 日志；需要错误通道时使用 `authorize()`。
    async fn has_all_permissions(&self, login_id: &str, perms: &[&str]) -> bool;
}

/// `PermissionChecker` 的默认实现，委托 `GarrisonInterface` 获取权限/角色数据后做字符串匹配。
///
/// 与 `GarrisonPermissionStrategy` 的职责区分：
/// - `PermissionCheckerDefault`：纯数据查询（返回 bool/Err，无副作用）
/// - `GarrisonPermissionStrategy`：编排（校验 + 抛异常 + 事件广播）
pub struct PermissionCheckerDefault {
    /// 业务接口（提供 get_permission_list / get_role_list）。
    interface: Arc<dyn GarrisonInterface>,
}

/// `PermissionCheckerDefault` 实现块（从 mod.rs 迁移，遵循mod.rs 接口隔离约定）。
pub mod default;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
