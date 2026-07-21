//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

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
#[cfg(feature = "permission-registry")]
pub mod registry;

#[cfg(feature = "permission-registry")]
pub use registry::{PermissionRegistration, PermissionRegistry, PermissionSpec};

/// 请求对象式授权器模块。
#[cfg(feature = "authorize-api")]
pub mod authorize;

#[cfg(feature = "authorize-api")]
pub use authorize::Authorizer;

/// 决策组合器模块（forbid 优先语义）。
#[cfg(feature = "safe-defaults")]
pub mod decision_combinator;

#[cfg(feature = "safe-defaults")]
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

    /// 鉴权决策：基于 [`AuthRequest`] 返回完整 [`Decision`]。
    ///
    /// 默认实现调用 [`has_permission`](Self::has_permission) 并构造 [`Decision`]：
    /// - 持有权限 → `Decision { allowed: true, reason: ExplicitAllow, .. }`
    /// - 未持有权限 → `Decision { allowed: false, reason: NoMatchingPermission, .. }`
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
        // D5（v0.5.1）：decision-trace feature 启用时自动生成 UUID v7 作为 trace_id
        // （时间有序，便于跨服务追踪与日志关联）；不启用时为 None，避免性能开销。
        #[cfg(feature = "decision-trace")]
        let trace_id = Some(uuid::Uuid::now_v7().to_string());
        #[cfg(not(feature = "decision-trace"))]
        let trace_id: Option<String> = None;

        let allowed = self
            .has_permission(&request.login_id, &request.action)
            .await?;
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
    /// 0.5.0 默认实现委托 [`authorize`](Self::authorize)，保持向后兼容。
    async fn check_permission(&self, login_id: &str, permission: &str) -> GarrisonResult<()> {
        let request = AuthRequest::new(login_id, permission);
        let decision = self.authorize(&request).await?;
        if decision.allowed {
            Ok(())
        } else {
            Err(GarrisonError::NotPermission(format!(
                "账号 {} 未持有权限: {}",
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
                "账号 {} 未持有角色: {}",
                login_id, role
            )))
        }
    }

    /// 批量校验权限：任一满足即返回 true。
    ///
    /// 内部调用 `has_permission`，遇到错误时该权限视为不满足。
    async fn has_any_permission(&self, login_id: &str, perms: &[&str]) -> bool;

    /// 批量校验权限：全部满足才返回 true。
    ///
    /// 内部调用 `has_permission`，遇到错误时该权限视为不满足。
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

/// `PermissionCheckerDefault` 实现块（从 mod.rs 迁移，遵循规则 25 mod.rs 接口隔离）。
pub mod default;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
